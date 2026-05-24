# Autores: Ronald Santos
import sys
import socket
import random
import struct

HEL, TRY, RES, BYE, ERR = 1, 2, 3, 4, 5

def calcular_checksum(dados_bytes):
    resultado = 0
    for byte in dados_bytes:
        resultado ^= byte
    return resultado

def validar_checksum(dados_rx):
    return calcular_checksum(dados_rx) == 0

def empacotar_mensagem(tipo, seqnum, payload=""):
    seqnum_net = seqnum & 0xFFFF
    
    formato_cabecalho = "!BBH"
    if tipo in (HEL, BYE, ERR):
        pct = struct.pack(formato_cabecalho, tipo, 0, seqnum_net)
    else:
        formato_longo = "!BBH8s"
        payload_bytes = payload.ljust(8, ' ').encode('ascii')
        pct = struct.pack(formato_longo, tipo, 0, seqnum_net, payload_bytes)
        
    checksum_real = calcular_checksum(pct)
    lista_bytes = list(pct)
    lista_bytes[1] = checksum_real
    return bytes(lista_bytes)

def desempacotar_mensagem(dados_rx):
    tamanho = len(dados_rx)
    if tamanho == 4:
        tipo, checksum, seqnum_unsigned = struct.unpack("!BBH", dados_rx)
        seqnum = seqnum_unsigned if seqnum_unsigned <= 32767 else seqnum_unsigned - 65536
        return tipo, checksum, seqnum, ""
    elif tamanho == 12:
        tipo, checksum, seqnum_unsigned, payload_bytes = struct.unpack("!BBH8s", dados_rx)
        seqnum = seqnum_unsigned if seqnum_unsigned <= 32767 else seqnum_unsigned - 65536
        return tipo, checksum, seqnum, payload_bytes.decode('ascii').strip()
    raise ValueError("Tamanho inválido")

def gerar_senha_aleatoria(tamanho):
    digitos = random.sample("0123456789", tamanho)
    return "".join(digitos)

def avaliar_tentativa(senha_real, tentativa):
    resultado = ""
    tentativa_truncada = tentativa[:len(senha_real)]
    for i in range(len(tentativa_truncada)):
        digito = tentativa_truncada[i]
        if digito == senha_real[i]:
            resultado += "*"
        elif digito in senha_real:
            resultado += "+"
        else:
            resultado += "-"
    return resultado

def iniciar_servidor(porta, senha_arg, nt_max):
    tamanho_senha = len(senha_arg)
    if senha_arg == "0" * tamanho_senha:
        senha_global = gerar_senha_aleatoria(tamanho_senha)
    else:
        senha_global = senha_arg
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', porta))

    clientes = {} 
    clientes_finalizados = 0

    while clientes_finalizados < 2:
        try:
            dados, endereco_cliente = sock.recvfrom(1024)
            
            if not validar_checksum(dados):
                continue
                
            tipo, checksum, seqnum, payload = desempacotar_mensagem(dados)
            
            if tipo == HEL:
                if endereco_cliente not in clientes:
                    clientes[endereco_cliente] = {
                        'tentativas_restantes': nt_max,
                        'seq_esperado': 1,
                        'ultima_resposta': None,
                        'finalizado': False
                    }
                
                resposta_str = "?" * tamanho_senha
                pacote_resposta = empacotar_mensagem(RES, nt_max, resposta_str)
                sock.sendto(pacote_resposta, endereco_cliente)
                clientes[endereco_cliente]['ultima_resposta'] = pacote_resposta
                
            elif tipo == TRY:
                if endereco_cliente not in clientes or clientes[endereco_cliente]['finalizado']:
                    pacote_err = empacotar_mensagem(ERR, 0)
                    sock.sendto(pacote_err, endereco_cliente)
                    continue
                
                estado = clientes[endereco_cliente]
                
                if seqnum == estado['seq_esperado'] - 1:
                    sock.sendto(estado['ultima_resposta'], endereco_cliente)
                    continue
                    
                if seqnum == estado['seq_esperado']:
                    palpite_real = payload[:tamanho_senha]
                    
                    if len(palpite_real) != tamanho_senha or len(set(palpite_real)) != len(palpite_real) or not palpite_real.isdigit():
                        pacote_err = empacotar_mensagem(ERR, seqnum)
                        sock.sendto(pacote_err, endereco_cliente)
                        # CORREÇÃO: Avança o seqnum mesmo no erro para manter sincronia e salva para stop-and-wait
                        estado['seq_esperado'] += 1
                        estado['ultima_resposta'] = pacote_err
                        continue

                    resultado = avaliar_tentativa(senha_global, palpite_real)
                    estado['tentativas_restantes'] -= 1
                    estado['seq_esperado'] += 1
                    
                    pacote_resposta = empacotar_mensagem(RES, estado['tentativas_restantes'], resultado)
                    sock.sendto(pacote_resposta, endereco_cliente)
                    estado['ultima_resposta'] = pacote_resposta

            elif tipo == BYE:
                if endereco_cliente in clientes:
                    estado = clientes[endereco_cliente]
                    if not estado['finalizado']:
                        pacote_resposta = empacotar_mensagem(RES, -1, senha_global)
                        sock.sendto(pacote_resposta, endereco_cliente)
                        
                        estado['finalizado'] = True
                        estado['ultima_resposta'] = pacote_resposta
                        clientes_finalizados += 1
                    else:
                        # CORREÇÃO: Se o BYE vier duplicado, retransmite a resposta do BYE
                        sock.sendto(estado['ultima_resposta'], endereco_cliente)
            
        except KeyboardInterrupt:
            break
        except Exception:
            continue
            
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(1)
    iniciar_servidor(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))