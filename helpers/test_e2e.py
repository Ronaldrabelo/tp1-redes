import os
import re
import subprocess
import unittest

WORK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REMOTE_HOST = os.environ.get('REMOTE_HOST', '')
REMOTE_PORT = int(os.environ.get('REMOTE_PORT', '0'))
REMOTE_PASSWORD = os.environ.get('REMOTE_PASSWORD', '')


def run_client(input_lines, timeout=10):
    stdin_data = '\n'.join(input_lines).encode()
    proc = subprocess.Popen(
        ['make', '-s', 'run_cli', f'arg1={REMOTE_HOST}', f'arg2={REMOTE_PORT}'],
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


class TestE2E(unittest.TestCase):

    def setUp(self):
        if not REMOTE_HOST or not REMOTE_PORT:
            self.skipTest('REMOTE_HOST e REMOTE_PORT não definidos')

    def test_hel_res_formato_valido(self):
        """Primeira resposta deve ter NA entre 4-8 e NT > 0."""
        linhas = run_client([])
        match = re.match(r'NA=(\d+), NT=(\d+)', linhas[0])
        self.assertIsNotNone(match, f'Formato inválido: {linhas[0]}')
        na, nt = int(match.group(1)), int(match.group(2))
        self.assertGreaterEqual(na, 4)
        self.assertLessEqual(na, 8)
        self.assertGreater(nt, 0)

    def test_bye_apos_hel_retorna_senha_valida(self):
        """BYE logo após HEL deve retornar senha com NA dígitos únicos."""
        linhas = run_client([])
        na = int(re.match(r'NA=(\d+)', linhas[0]).group(1))
        self.assertTrue(linhas[-1].startswith('Senha='), f'Última linha: {linhas[-1]}')
        senha = linhas[-1].split('=')[1]
        self.assertEqual(len(senha), na)
        self.assertTrue(all(c.isdigit() for c in senha))
        self.assertEqual(len(set(senha)), na)  # sem repetições

    def test_try_digito_repetido_retorna_retry(self):
        """TRY com dígitos repetidos deve retornar RETRY."""
        # '00000000' tem todos os dígitos iguais — inválido para qualquer NA
        linhas = run_client(['00000000'])
        self.assertEqual(linhas[1], 'RETRY 1')

    def test_try_valido_retorna_padrao_avaliacao(self):
        """TRY com guess sem repetição deve retornar padrão com *, + ou -."""
        # '01234567' tem dígitos únicos — válido para qualquer NA entre 4-8
        linhas = run_client(['01234567'])
        match = re.match(r'1\(\d+\) ([*+\-]+)', linhas[1])
        self.assertIsNotNone(match, f'Formato inesperado: {linhas[1]}')
        self.assertTrue(all(c in '*+-' for c in match.group(1)))

    def test_tentativas_restantes_decresce(self):
        """Seqnum da resposta deve decrementar a cada TRY."""
        linhas = run_client(['01234567', '12345678'])
        _, nt = re.match(r'NA=(\d+), NT=(\d+)', linhas[0]).groups()
        nt = int(nt)
        remaining1 = int(re.match(r'1\((\d+)\)', linhas[1]).group(1))
        remaining2 = int(re.match(r'2\((\d+)\)', linhas[2]).group(1))
        self.assertEqual(remaining1, nt - 1)
        self.assertEqual(remaining2, nt - 2)

    def test_acerto_com_senha_descoberta(self):
        """Acerta a senha após descobri-la via BYE em sessão anterior."""
        # Primeira sessão: descobre a senha
        linhas = run_client([])
        senha = linhas[-1].split('=')[1]

        # Segunda sessão: envia a senha correta como TRY
        linhas = run_client([senha])
        match = re.match(r'1\(\d+\) ([*]+)', linhas[1])
        self.assertIsNotNone(match, f'Esperado acerto total, recebeu: {linhas[1]}')
        self.assertTrue(all(c == '*' for c in match.group(1)))

    def test_esgotamento_recebe_senha_no_bye(self):
        """Após esgotar NT tentativas, BYE ainda retorna a senha correta."""
        na_nt = re.match(r'NA=(\d+), NT=(\d+)', run_client([])[0])
        na, nt = int(na_nt.group(1)), int(na_nt.group(2))

        # Gera NT palpites válidos (sem repetição interna) rotacionando os dígitos
        palpites = [''.join(str((i + j) % 10) for j in range(na)) for i in range(nt)]
        linhas = run_client(palpites)

        self.assertTrue(linhas[-1].startswith('Senha='), f'Última linha: {linhas[-1]}')
        senha = linhas[-1].split('=')[1]
        self.assertEqual(len(senha), na)
        self.assertEqual(len(set(senha)), na)


    @unittest.skipUnless(REMOTE_PASSWORD, 'REMOTE_PASSWORD não definido')
    def test_acerto_com_senha_conhecida(self):
        """Envia a senha correta como primeiro TRY e verifica acerto total."""
        linhas = run_client([REMOTE_PASSWORD])
        na = int(re.match(r'NA=(\d+)', linhas[0]).group(1))
        match = re.match(r'1\(\d+\) ([*]+)', linhas[1])
        self.assertIsNotNone(match, f'Esperado acerto total, recebeu: {linhas[1]}')
        self.assertEqual(match.group(1), '*' * na)

    @unittest.skipUnless(REMOTE_PASSWORD, 'REMOTE_PASSWORD não definido')
    def test_padrao_exato_para_palpite_conhecido(self):
        """Verifica avaliação *+- de forma determinística com palpite calculado."""
        pw = list(REMOTE_PASSWORD)
        na = len(pw)

        # Rotaciona a senha em 1 posição: dígitos certos mas todos na posição errada (+)
        # exceto quando um dígito rotacionado cai na posição certa por coincidência
        palpite = pw[1:] + pw[:1]
        esperado = ''
        for i, d in enumerate(palpite):
            if d == pw[i]:
                esperado += '*'
            elif d in pw:
                esperado += '+'
            else:
                esperado += '-'

        linhas = run_client([''.join(palpite)])
        match = re.match(r'1\(\d+\) ([*+\-]+)', linhas[1])
        self.assertIsNotNone(match, f'Formato inesperado: {linhas[1]}')
        self.assertEqual(match.group(1), esperado)

    @unittest.skipUnless(REMOTE_PASSWORD, 'REMOTE_PASSWORD não definido')
    def test_sequencia_completa_com_senha_conhecida(self):
        """Envia palpites errados conhecidos e acerta na última tentativa."""
        pw = list(REMOTE_PASSWORD)
        na = len(pw)

        # Palpite errado: rotação da senha (todos os dígitos presentes, posições trocadas)
        palpite_errado = ''.join(pw[1:] + pw[:1])
        esperado_errado = ''
        for i, d in enumerate(pw[1:] + pw[:1]):
            if d == pw[i]:
                esperado_errado += '*'
            elif d in pw:
                esperado_errado += '+'
            else:
                esperado_errado += '-'

        linhas = run_client([palpite_errado, REMOTE_PASSWORD])

        match_errado = re.match(r'1\(\d+\) ([*+\-]+)', linhas[1])
        self.assertIsNotNone(match_errado, f'Formato inesperado: {linhas[1]}')
        self.assertEqual(match_errado.group(1), esperado_errado)

        match_acerto = re.match(r'2\(\d+\) ([*]+)', linhas[2])
        self.assertIsNotNone(match_acerto, f'Esperado acerto total: {linhas[2]}')
        self.assertEqual(match_acerto.group(1), '*' * na)

    @unittest.skipUnless(REMOTE_PASSWORD, 'REMOTE_PASSWORD não definido')
    def test_retry_depois_de_digito_repetido_acerta(self):
        """Após RETRY por dígito repetido, envia senha correta e verifica acerto."""
        na = len(REMOTE_PASSWORD)
        linhas = run_client(['00000000', REMOTE_PASSWORD])
        self.assertEqual(linhas[1], 'RETRY 1')
        # após RETRY a tentativa avança para 2
        match = re.match(r'2\(\d+\) ([*]+)', linhas[2])
        self.assertIsNotNone(match, f'Esperado acerto total: {linhas[2]}')
        self.assertEqual(match.group(1), '*' * na)


if __name__ == '__main__':
    unittest.main(verbosity=2)
