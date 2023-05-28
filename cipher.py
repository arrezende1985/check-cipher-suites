# @Author: Alexandre Rezende
# @Date:   2023-05-23 11:27:30

import datetime
import base64
import binascii
import contextlib
import ipaddress
import os
import socket
import ssl
import warnings
from collections import defaultdict
from ipwhois import IPWhois


# Cores ANSI
class Cores:
    VERMELHO = '\033[91m'
    VERDE = '\033[92m'
    AMARELO = '\033[93m'
    AZUL = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'


def verifica_ciphersuite_protocolo(host, porta):
    # Cria um contexto SSL/TLS personalizado
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Desativa a verificação do certificado
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE

    # Obtém todas as ciphersuites suportadas pelo contexto
    ciphersuites = contexto.get_ciphers()

    # Agrupa as ciphersuites por versão do TLS
    ciphersuites_por_versao = defaultdict(list)
    for ciphersuite in ciphersuites:
        versao_tls = ciphersuite['protocol']
        ciphersuites_por_versao[versao_tls].append(ciphersuite)

    # Exibe as ciphersuites por versão do TLS
    print(f"{Cores.AZUL}Ciphersuites compatíveis:{Cores.RESET}")
    for versao_tls, ciphersuites in ciphersuites_por_versao.items():
        print(f"{Cores.AMARELO}Versão do protocolo TLS: {versao_tls}{Cores.RESET}")
        for ciphersuite in ciphersuites:
            print(f"  {Cores.VERDE}Algoritmo:{Cores.RESET} {ciphersuite['name']}")
            if 'keySize' in ciphersuite:
                print(f"  {Cores.VERDE}Bits da chave:{Cores.RESET} {ciphersuite['keySize']}")
        print()

def obter_enderecos_ip(host):
    # Obtém uma lista de endereços IP do host
    enderecos_ip = socket.gethostbyname_ex(host)[2]

    # Verifica se há endereços IP disponíveis
    if len(enderecos_ip) > 0:
        print(f"{Cores.AMARELO}Endereços IP:{Cores.RESET}")
        for ip in enderecos_ip:
            print(f"  {Cores.AMARELO}Endereço IP:{Cores.RESET} {ip}")

            # Verifica o tipo de IP (Internet ou Rede Interna)
            obj = IPWhois(ip)
            info = obj.lookup_rdap()
            if info['asn_country_code']:
                print(f"    {Cores.AMARELO}Tipo de IP:{Cores.RESET} Internet")
                print(f"    {Cores.AMARELO}Localização:{Cores.RESET} {info['asn_country_code']} - {info['asn_description']}")
            else:
                print(f"    {Cores.AMARELO}Tipo de IP:{Cores.RESET} Rede Interna")
            print()
    else:
        print(f"{Cores.AMARELO}Nenhum endereço IP encontrado para o host {host}{Cores.RESET}")


# Limpa o terminal
def limpar_terminal():
    if os.name == 'posix':  # Sistema tipo Unix
        os.system('clear')
    elif os.name == 'nt':  # Sistema Windows
        os.system('cls')


def main():
    limpar_terminal()
    host = input("Digite o host: ")
    porta = int(input("Digite a porta: "))

    limpar_terminal()
    obter_enderecos_ip(host)
    verifica_ciphersuite_protocolo(host, porta)


if __name__ == '__main__':
    main()
