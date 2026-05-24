import os
import socket
import struct
import subprocess
import threading
import time
import unittest

HEL, TRY, RES, BYE, ERR = 1, 2, 3, 4, 5

WORK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def xor_checksum(data):
    result = 0
    for i, b in enumerate(data):
        if i != 1:
            result ^= b
    return result


def build_msg(tipo, seqnum, payload=b''):
    seqnum_bytes = struct.pack('!H', seqnum & 0xFFFF)
    raw = bytes([tipo, 0]) + seqnum_bytes + payload
    cs = xor_checksum(raw)
    return bytes([tipo, cs]) + seqnum_bytes + payload

def parse_msg(data):
    tipo = data[0]
    seqnum = struct.unpack('!H', data[2:4])[0]
    payload = data[4:] if len(data) > 4 else b''
    return tipo, seqnum, payload

def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server(port, password, NT):
    return subprocess.Popen(
        ['make', '-s', 'run_serv', f'arg1={port}', f'arg2={password}', f'arg3={NT}'],
        cwd=WORK_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

def run_client(port, input_lines, timeout=5):
    stdin_data = '\n'.join(input_lines).encode()
    proc = subprocess.Popen(
        ['make', '-s', 'run_cli', 'arg1=localhost', f'arg2={port}'],
        cwd=WORK_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        stdout, _ = proc.communicate(input=stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()
    return stdout.decode().splitlines()

def drain_server(port):
    try:
        run_client(port, [], timeout=3)
    except Exception:
        pass
class TestIntegration(unittest.TestCase):

    # --- helpers: servidor real + cliente real ---

    def _run(self, password, NT, palpites, timeout=10):
        port = find_free_port()
        srv = start_server(port, password, NT)
        time.sleep(0.2)
        try:
            linhas = run_client(port, palpites, timeout=timeout)
        finally:
            drain_server(port)
            srv.kill()
            srv.wait()
        return linhas

    def _fake_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        sock.settimeout(5.0)
        port = sock.getsockname()[1]
        return sock, port

    def _launch_client(self, port, input_lines, client_timeout=12):
        stdin_data = '\n'.join(input_lines).encode()
        proc = subprocess.Popen(
            ['make', '-s', 'run_cli', 'arg1=localhost', f'arg2={port}'],
            cwd=WORK_DIR,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        result = [None]

        def io_worker():
            try:
                stdout, _ = proc.communicate(input=stdin_data, timeout=client_timeout)
                result[0] = stdout.decode().splitlines()
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
                result[0] = stdout.decode().splitlines()

        t = threading.Thread(target=io_worker, daemon=True)
        t.start()
        return proc, t, result

    def _full_session(self, sock, addr, password='2345', NT=6):
        """Conduz TRYs e BYE normalmente após o HEL já ter sido tratado."""
        NA = len(password)
        pw = [int(c) for c in password]

        def evaluate(guess):
            result = []
            for i, g in enumerate(guess):
                if g == pw[i]:
                    result.append('*')
                elif g in pw:
                    result.append('+')
                else:
                    result.append('-')
            return ''.join(result)

        while True:
            try:
                data, a = sock.recvfrom(2048)
            except socket.timeout:
                break
            if a != addr:
                continue
            tipo, seqnum, payload = parse_msg(data)
            if tipo == TRY:
                guess = list(payload[:NA])
                res = evaluate(guess)
                remaining = NT - seqnum
                pat = bytes([ord(c) for c in res] + [ord(' ')] * (8 - NA))
                sock.sendto(build_msg(RES, remaining, pat), addr)
                if res == '*' * NA or remaining == 0:
                    break
            elif tipo == BYE:
                pw_bytes = bytes([ord(c) for c in password] + [ord(' ')] * (8 - NA))
                sock.sendto(build_msg(RES, 0xFFFF, pw_bytes), addr)
                break

    def test_exemplo_enunciado(self):
        """Sequência exata do exemplo do enunciado."""
        linhas = self._run('2345', 6, ['2154', '2495', '2745', '2345'])
        self.assertEqual(linhas, [
            'NA=4, NT=6',
            '1(5) *-++',
            '2(4) *+-*',
            '3(3) *-**',
            '4(2) ****',
            'Senha=2345',
        ])

    def test_acerto_primeira_tentativa(self):
        linhas = self._run('1234', 5, ['1234'])
        self.assertEqual(linhas[0], 'NA=4, NT=5')
        self.assertEqual(linhas[1], '1(4) ****')
        self.assertEqual(linhas[-1], 'Senha=1234')

    def test_esgotamento_tentativas(self):
        linhas = self._run('1234', 3, ['5678', '5679', '5670'])
        self.assertEqual(linhas[0], 'NA=4, NT=3')
        self.assertIn('1(2)', linhas[1])
        self.assertIn('2(1)', linhas[2])
        self.assertIn('3(0)', linhas[3])
        self.assertEqual(linhas[-1], 'Senha=1234')

    def test_palpite_invalido_retry(self):
        # 2234 tem dígito 2 repetido — deve gerar RETRY 1
        linhas = self._run('2345', 6, ['2234', '2154'])
        self.assertEqual(linhas[0], 'NA=4, NT=6')
        self.assertEqual(linhas[1], 'RETRY 1')
        self.assertIn('2(', linhas[2])
        self.assertEqual(linhas[-1], 'Senha=2345')

    def test_bye_sem_try(self):
        linhas = self._run('2345', 6, [])
        self.assertEqual(linhas[0], 'NA=4, NT=6')
        self.assertEqual(linhas[-1], 'Senha=2345')

    def test_senha_8_digitos(self):
        linhas = self._run('98765432', 5, ['98765432'])
        self.assertEqual(linhas[0], 'NA=8, NT=5')
        self.assertEqual(linhas[1], '1(4) ********')
        self.assertEqual(linhas[-1], 'Senha=98765432')

    def test_senha_aleatoria(self):
        """Senha '0000' faz o servidor gerar senha aleatória de 4 dígitos sem repetição."""
        linhas = self._run('0000', 5, [])
        self.assertEqual(linhas[0], 'NA=4, NT=5')
        self.assertTrue(linhas[-1].startswith('Senha='))
        senha = linhas[-1].split('=')[1]
        self.assertEqual(len(senha), 4)
        self.assertTrue(all(c.isdigit() for c in senha))
        self.assertEqual(len(set(senha)), 4)

    def test_acerto_medio_jogo_aguarda_eof(self):
        """Após acerto, cliente não encerra automaticamente — aguarda EOF."""
        # NT=6; acerta na tentativa 2, ainda envia a tentativa 3 antes do EOF
        linhas = self._run('2345', 6, ['9876', '2345', '1357'])
        self.assertEqual(linhas[0], 'NA=4, NT=6')
        self.assertEqual(linhas[2], '2(4) ****')   # acertou na 2ª tentativa
        self.assertIn('3(', linhas[3])              # continuou após o acerto
        self.assertEqual(linhas[-1], 'Senha=2345')  # BYE enviado só após EOF

    def test_bye_duplicado_recebe_mesmo_res(self):
        """BYE retransmitido deve receber o mesmo RES (stop-and-wait no BYE)."""
        port = find_free_port()
        srv = start_server(port, '2345', 6)
        time.sleep(0.2)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        addr = ('127.0.0.1', port)
        try:
            sock.sendto(build_msg(HEL, 0), addr)
            sock.recvfrom(2048)
            sock.sendto(build_msg(BYE, 0), addr)
            data1, _ = sock.recvfrom(2048)
            sock.sendto(build_msg(BYE, 0), addr)
            data2, _ = sock.recvfrom(2048)
        finally:
            sock.close()
            drain_server(port)
            srv.kill()
            srv.wait()
        tipo1, seq1, pay1 = parse_msg(data1)
        tipo2, seq2, pay2 = parse_msg(data2)
        self.assertEqual(tipo1, RES)
        self.assertEqual(tipo2, RES)
        self.assertEqual(seq1, seq2)
        self.assertEqual(pay1, pay2)

    def test_dois_clientes_sequenciais(self):
        port = find_free_port()
        srv = start_server(port, '2345', 6)
        time.sleep(0.2)

        l1 = run_client(port, ['2345'])
        l2 = run_client(port, ['2345'])

        try:
            srv.wait(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait()

        self.assertEqual(l1[-1], 'Senha=2345')
        self.assertEqual(l2[-1], 'Senha=2345')
        self.assertEqual(srv.returncode, 0)

    def test_dois_clientes_concorrentes(self):
        port = find_free_port()
        srv = start_server(port, '2345', 6)
        time.sleep(0.2)

        resultados = [None, None]

        def cliente(i, palpites):
            resultados[i] = run_client(port, palpites, timeout=10)

        t1 = threading.Thread(target=cliente, args=(0, ['2154', '2345']))
        t2 = threading.Thread(target=cliente, args=(1, ['9876', '2345']))
        t1.start()
        t2.start()
        t1.join(timeout=12)
        t2.join(timeout=12)

        try:
            srv.wait(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait()

        for i in range(2):
            self.assertIsNotNone(resultados[i], f'Cliente {i+1} não retornou')
            self.assertEqual(resultados[i][-1], 'Senha=2345',
                             f'Cliente {i+1} não recebeu a senha correta')

    def test_no_res(self):
        """Sem resposta após 3 timeouts, cliente deve imprimir NO RES."""
        port = find_free_port()  # porta livre sem servidor ouvindo
        linhas = run_client(port, [], timeout=10)
        self.assertIn('NO RES', linhas)

    def test_timeout_no_hel(self):
        """Servidor ignora o 1º HEL; cliente retransmite e recebe resposta."""
        sock, port = self._fake_server()
        _, io_thread, result = self._launch_client(port, ['2154'])

        NA = 4
        pat = bytes([ord('?')] * NA + [ord(' ')] * (8 - NA))

        data, addr = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data)[0], HEL)   # 1ª transmissão — descarta

        data2, addr2 = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data2)[0], HEL)  # retransmissão — responde
        sock.sendto(build_msg(RES, 6, pat), addr2)
        self._full_session(sock, addr2)
        sock.close()

        io_thread.join(timeout=12)
        linhas = result[0] or []
        self.assertNotIn('NO RES', linhas)
        self.assertEqual(linhas[0], 'NA=4, NT=6')

    def test_pacote_corrompido_no_hel(self):
        """Servidor envia RES corrompido para HEL; cliente retransmite HEL."""
        sock, port = self._fake_server()
        _, io_thread, result = self._launch_client(port, ['2154'])

        NA = 4
        pat = bytes([ord('?')] * NA + [ord(' ')] * (8 - NA))
        res_correto = build_msg(RES, 6, pat)

        data, addr = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data)[0], HEL)
        corrompido = bytes([res_correto[0], res_correto[1] ^ 0xFF]) + res_correto[2:]
        sock.sendto(corrompido, addr)

        data2, addr2 = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data2)[0], HEL)  # retransmissão
        sock.sendto(res_correto, addr2)
        self._full_session(sock, addr2)
        sock.close()

        io_thread.join(timeout=12)
        linhas = result[0] or []
        self.assertNotIn('NO RES', linhas)
        self.assertEqual(linhas[0], 'NA=4, NT=6')

    def test_timeout_no_try(self):
        """Servidor ignora o 1º TRY; cliente retransmite e recebe resposta."""
        sock, port = self._fake_server()
        _, io_thread, result = self._launch_client(port, ['2154'])

        NA = 4
        hel_res = build_msg(RES, 6, bytes([ord('?')] * NA + [ord(' ')] * (8 - NA)))
        try_res = build_msg(RES, 5, bytes([ord('*'), ord('-'), ord('+'), ord('+'),
                                           ord(' '), ord(' '), ord(' '), ord(' ')]))
        bye_res = build_msg(RES, 0xFFFF, bytes([ord('2'), ord('3'), ord('4'), ord('5'),
                                                ord(' '), ord(' '), ord(' '), ord(' ')]))

        data, addr = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data)[0], HEL)
        sock.sendto(hel_res, addr)

        data, addr = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data)[0], TRY)   # 1ª transmissão — descarta

        data2, addr2 = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data2)[0], TRY)  # retransmissão — responde
        sock.sendto(try_res, addr2)

        data3, addr3 = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data3)[0], BYE)
        sock.sendto(bye_res, addr3)

        sock.close()
        io_thread.join(timeout=12)
        linhas = result[0] or []
        self.assertNotIn('NO RES', linhas)
        self.assertEqual(linhas[0], 'NA=4, NT=6')
        self.assertIn('1(5)', linhas[1])
        self.assertEqual(linhas[-1], 'Senha=2345')

    def test_pacote_corrompido_no_try(self):
        """Servidor envia RES corrompido para TRY; cliente retransmite TRY."""
        sock, port = self._fake_server()
        _, io_thread, result = self._launch_client(port, ['2154'])

        NA = 4
        hel_res = build_msg(RES, 6, bytes([ord('?')] * NA + [ord(' ')] * (8 - NA)))
        try_res = build_msg(RES, 5, bytes([ord('*'), ord('-'), ord('+'), ord('+'),
                                           ord(' '), ord(' '), ord(' '), ord(' ')]))
        bye_res = build_msg(RES, 0xFFFF, bytes([ord('2'), ord('3'), ord('4'), ord('5'),
                                                ord(' '), ord(' '), ord(' '), ord(' ')]))

        data, addr = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data)[0], HEL)
        sock.sendto(hel_res, addr)

        data, addr = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data)[0], TRY)
        corrompido = bytes([try_res[0], try_res[1] ^ 0xFF]) + try_res[2:]
        sock.sendto(corrompido, addr)

        data2, addr2 = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data2)[0], TRY)  # retransmissão
        sock.sendto(try_res, addr2)

        data3, addr3 = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data3)[0], BYE)
        sock.sendto(bye_res, addr3)

        sock.close()
        io_thread.join(timeout=12)
        linhas = result[0] or []
        self.assertNotIn('NO RES', linhas)
        self.assertEqual(linhas[0], 'NA=4, NT=6')
        self.assertIn('1(5)', linhas[1])
        self.assertEqual(linhas[-1], 'Senha=2345')

    def test_pacote_corrompido_no_bye(self):
        """Servidor envia RES corrompido para BYE; cliente retransmite BYE."""
        sock, port = self._fake_server()
        _, io_thread, result = self._launch_client(port, [])  # EOF imediato → BYE

        NA = 4
        hel_res = build_msg(RES, 6, bytes([ord('?')] * NA + [ord(' ')] * (8 - NA)))
        bye_res = build_msg(RES, 0xFFFF, bytes([ord('2'), ord('3'), ord('4'), ord('5'),
                                                ord(' '), ord(' '), ord(' '), ord(' ')]))

        data, addr = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data)[0], HEL)
        sock.sendto(hel_res, addr)

        data, addr = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data)[0], BYE)
        corrompido = bytes([bye_res[0], bye_res[1] ^ 0xFF]) + bye_res[2:]
        sock.sendto(corrompido, addr)

        data2, addr2 = sock.recvfrom(2048)
        self.assertEqual(parse_msg(data2)[0], BYE)  # retransmissão
        sock.sendto(bye_res, addr2)

        sock.close()
        io_thread.join(timeout=12)
        linhas = result[0] or []
        self.assertNotIn('NO RES', linhas)
        self.assertEqual(linhas[0], 'NA=4, NT=6')
        self.assertEqual(linhas[-1], 'Senha=2345')

if __name__ == '__main__':
    unittest.main(verbosity=2)
