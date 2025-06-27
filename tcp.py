import asyncio
from collections import deque
from math import ceil
import random
import time
from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('Descartando segmento com "checksum" incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no)

            seq_envio = random.randint(0, 0xffff)
            ack_envio = seq_no + 1
            segment = make_header(dst_port, src_port, seq_envio, ack_envio, FLAGS_SYN | FLAGS_ACK)
            response = fix_checksum(segment, dst_addr, src_addr)
            self.rede.enviar(response, src_addr)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.seq_envio = random.randint(0, 0xffff)
        self.seq_no_eperado = seq_no + 1
        self.seq_no_comprimento = ack_no
        self.fila_seguimentos_enviados = deque()
        self.fila_seguimentos_esperando = deque()
        self.comprimento_seguimentos_enviados = 0
        self.tamanho_janela = 1 * MSS
        self.checado = False
        self.SampleRTT = 1
        self.EstimatedRTT = self.SampleRTT
        self.DevRTT = self.SampleRTT/2
        self.TimeoutInterval = 1
        self.timer = None 

    def _temporizador(self):
        self.timer = None
        self.tamanho_janela = self.tamanho_janela/2
        if self.fila_seguimentos_enviados:
            segment, addr, len_dados = self.fila_seguimentos_enviados.popleft()[1:]
            self.fila_seguimentos_enviados.appendleft((0, segment, addr, len_dados))
            self.servidor.rede.enviar(segment, addr)
            self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._temporizador)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if (flags & FLAGS_FIN == FLAGS_FIN):
            self.callback(self, b'')
            self.seq_no_comprimento = ack_no
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            segment = make_header(dst_port, src_port, self.seq_envio, self.seq_no_eperado + 1, flags)
            response = fix_checksum(segment, dst_addr, src_addr)
            self.servidor.rede.enviar(response, src_addr)

        elif seq_no == self.seq_no_eperado:
            self.seq_no_eperado += (len(payload) if payload else 0)
            self.callback(self, payload)
            self.seq_no_comprimento = ack_no

            if (flags & FLAGS_ACK) == FLAGS_ACK:
                if payload:
                    src_addr, src_port, dst_addr, dst_port = self.id_conexao
                    segment = make_header(dst_port, src_port, self.seq_envio, self.seq_no_eperado, flags)
                    response = fix_checksum(segment, dst_addr, src_addr)
                    self.servidor.rede.enviar(response, src_addr)

                existe_fila_segmentos_esperando = self.comprimento_seguimentos_enviados > 0

                if self.timer:
                    self.timer.cancel()
                    self.timer = None
                    while self.fila_seguimentos_enviados:
                        firstTime, segmento, _, len_dados = self.fila_seguimentos_enviados.popleft()
                        self.comprimento_seguimentos_enviados -= len_dados
                        seq = read_header(segmento)[2]
                        if seq == ack_no:
                            break
                    if firstTime:
                        self.SampleRTT = time.time() - firstTime
                        if self.checado == False:
                            self.checado = True
                            self.EstimatedRTT = self.SampleRTT
                            self.DevRTT = self.SampleRTT / 2
                        else:
                            self.EstimatedRTT = (1 - 0.125) * self.EstimatedRTT + 0.125 * self.SampleRTT
                            self.DevRTT = (1 - 0.25) * self.DevRTT + 0.25 * abs(self.SampleRTT - self.EstimatedRTT)
                        self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT

                nenhum_comprimento_seguimentos_enviados = self.comprimento_seguimentos_enviados == 0
                if existe_fila_segmentos_esperando and nenhum_comprimento_seguimentos_enviados:
                    self.tamanho_janela += MSS

                while self.fila_seguimentos_esperando:
                    response, src_addr, len_dados = self.fila_seguimentos_esperando.popleft()
                    if self.comprimento_seguimentos_enviados + len_dados > self.tamanho_janela:
                        self.fila_seguimentos_esperando.appendleft((response, src_addr, len_dados))
                        break
                    self.comprimento_seguimentos_enviados += len_dados
                    self.servidor.rede.enviar(response, src_addr)
                    self.fila_seguimentos_enviados.append((time.time(), response, src_addr, len_dados))

                if self.fila_seguimentos_enviados:
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._temporizador)

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        size = ceil(len(dados)/MSS)
        for i in range(size):
            self.seq_envio = self.seq_no_comprimento
            segment = make_header(dst_port, src_port, self.seq_envio, self.seq_no_eperado, flags=FLAGS_ACK)
            segment += (dados[ i * MSS : min((i + 1) * MSS, len(dados))])
            len_dados = len(dados[i * MSS : min((i + 1) * MSS, len(dados))])
            self.seq_no_comprimento += len_dados
            response = fix_checksum(segment, dst_addr, src_addr)
            if self.comprimento_seguimentos_enviados + len_dados <= self.tamanho_janela:
                self.servidor.rede.enviar(response, src_addr)
                self.fila_seguimentos_enviados.append((time.time(), response, src_addr, len_dados))
                self.comprimento_seguimentos_enviados += len_dados
                if not self.timer:
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._temporizador)
            else:
                self.fila_seguimentos_esperando.append((response, src_addr, len_dados))       

    def fechar(self):
        self.seq_envio = self.seq_no_comprimento
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        segment = make_header(dst_port, src_port, self.seq_envio, self.seq_no_eperado + 1, FLAGS_FIN)
        response = fix_checksum(segment, dst_addr, src_addr)
        self.servidor.rede.enviar(response, src_addr)
