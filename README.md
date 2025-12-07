# Right Here Waiting (Proj_SSI)

> **Sistema de Comunicação Seguro e Pós-Quântico (TUI)**

![Python](https://img.shields.io/badge/Language-Python-3776AB?logo=python&logoColor=white)
![Textual](https://img.shields.io/badge/Framework-Textual-green)
![Security](https://img.shields.io/badge/Security-Post--Quantum-blue)

## Visão Geral

**Right Here Waiting** é um sistema de software desenvolvido no âmbito da unidade curricular de **Segurança de Sistemas Informáticos (SSI)**.

O projeto implementa uma interface de terminal moderna (TUI) para permitir a proteção de ficheiros e comunicações seguras, assegurando robustez contra a ameaça da computação quântica (**Criptografia Pós-Quântica**), utilizando algoritmos como o esquema de assinaturas de Lamport.

## Funcionalidades

A aplicação dispõe de uma Interface de Utilizador no Terminal (TUI) com os seguintes módulos:

### 1. Gestão de Chaves
* **Chaves de Cifra**: Geração de chaves simétricas.
* **Chaves Lamport**: Geração de pares de chaves (pública/privada) resistentes a computadores quânticos.

### 2. Cifra e Decifra
* **Cifrar Ficheiro**: Garante a confidencialidade dos dados.
* **Decifrar Ficheiro**: Restaura o ficheiro original.

### 3. Assinaturas Digitais (Lamport)
* **Assinar Ficheiro**: Criação de assinaturas digitais pós-quânticas.
* **Verificar Assinatura**: Validação da autenticidade e origem do ficheiro.

### 4. Integridade (MAC/HMAC)
* **Gerar e Verificar**: Garante que o ficheiro não sofreu alterações não autorizadas.

## 📋 Pré-requisitos

Para executar este projeto, necessitas de:

1.  **Python 3.8** ou superior.
2.  **Textual**: Biblioteca para a interface gráfica no terminal.

## Instalação

1.  **Clonar o repositório:**
    ```bash
    git clone [https://github.com/JeyCraftPT/Proj_SSI.git](https://github.com/JeyCraftPT/Proj_SSI.git)
    cd Proj_SSI
    ```

2.  **Navegar para a diretoria do projeto:**
    ```bash
    cd rightHereWaiting
    ```

3.  **Instalar dependências:**
    O projeto utiliza o `Textual` para a interface. Instala as dependências (e outras bibliotecas criptográficas necessárias):
    ```bash
    pip install textual textual-dev pycryptodome
    ```

## Como Executar

Para iniciar a aplicação TUI, certifica-te de que estás dentro da pasta `rightHereWaiting` e executa o seguinte comando:

```bash
python -m src.main
