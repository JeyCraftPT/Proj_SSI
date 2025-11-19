# Proj_SSI

## Right Here Waiting

Objetivo deste consiste em desenvolver uma aplicação ou um sistema de software que permita a proteção de ficheiros, assegurando que essa proteção se mantém mesmo que apareça um computador quântico.

# Funcionalidades do Sistema

O programa a desenvolver deverá disponibilizar ao utilizador um conjunto de funcionalidades básicas relacionadas com criptografia, integridade e assinaturas digitais, incluindo suporte para o esquema de assinaturas de Lamport.

## 1. Gestão de Chaves

- Gerar chaves de cifra

  - Permite criar chaves para operações de cifrar e decifrar.

- Gerar chaves de assinatura digital (Lamport

  - Criação de par de chaves pública/privada para o esquema de Lamport.

- (Opcional) Suporte a múltiplos utilizadores
  - Cada utilizador possui o seu próprio conjunto de chaves.
  - As chaves privadas podem ser guardadas de forma segura numa base de dados.

## 2. Cifra e Decifra de Ficheiros

- Cifrar ficheiro

  - O programa solicita:
    - Ficheiro de entrada.
    - Chave de cifra.
    - Ficheiro de saída.

- Decifrar ficheiro
  - O programa solicita:
    - Ficheiro cifrado.
    - Chave de cifra.
    - Ficheiro de saída.

## 3. Assinaturas Digitais (Lamport)

- Criar assinatura

  - O programa solicita:
    - Ficheiro a assinar.
    - Chave privada do utilizador.
  - Gera uma assinatura digital utilizando Lamport.

- **Verificar assinatura**
  - O programa solicita:
    - Ficheiro original.
    - Ficheiro com a assinatura.
    - Chave pública correspondente.
  - Informa se a assinatura é válida ou inválida.

## 4. Código de Autenticação de Mensagens (MAC/HMAC)

- **Gerar código de integridade**

  - Criação de um código que assegura a integridade e autenticidade da mensagem ou ficheiro.

- **Verificar código de integridade**
  - O programa solicita:
    - Ficheiro de origem.
    - Código de autenticação.
    - Chave associada.
  - Valida se o ficheiro sofreu alterações.

## 5. Interface de Utilização

- **Interativo e amigável**

  - Ao abrir o programa, apresenta-se um menu com as opções, como:
    1. Gerar chave de cifra
    2. Gerar chave de assinatura (Lamport)
    3. Cifrar ficheiro
    4. Decifrar ficheiro
    5. Assinar ficheiro
    6. Verificar assinatura
    7. Criar código de autenticação
    8. Verificar código de autenticação
    9. Sair

- **Fluxo orientado**

  - Após escolher uma opção, o programa guia o utilizador passo a passo até ao resultado final.
