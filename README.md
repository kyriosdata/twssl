# Two way ssl with JWT - TCC 2 UFG SI
O acesso à informação em saúde é possível apenas em cenários restritos e bem definidos. Para requisitar qualquer informação à RNDS, por exemplo, primeiro é preciso obter um token de acesso. A obtenção ocorre por meio de serviço específico.

A requisição para este serviço é GET /api/token. O token só será recuperado por esta requisição se o certificado digital empregando por quem efetua esta requisição já estiver devidamente configurado com o serviço. Esta requisição usa Two Way SSL como mecanismo de autenticação. Se o resultado é positivo, então retornará um JWT. Caso contrário, a requisição falha.
## Version 1
- Client side SSL
- Spring security with basic auth
- certificate folder

## Version 2
- Server side ssl replacing basic auth
- new files in certificate folder
  
## Version 3
- Full implementation of /certificate endpoint
- Ssl context reload
- Mock for certificate alias search (later should be replaced for database)

## Version 4
- Replacement of enpoints '/autorizado' for '/verify'
- Dinamic memory-only/filed truststore

##Version 5
- Asymmetric JWT secrect for generation and validation 

# Estratégia para geração de certificado e importação em truststore

Nesse projeto é utilizado autenticação por certificado X.509. Ou seja enquanto uma conexão segura é estabelecida, o cliente verifica o servidor de acordo com seu certificado (emitido por uma autoridade de certificação confiável).

Mas além disso, no Spring Security, o X.509 pode ser usado para verificar a identidade de um cliente pelo servidor durante a conexão. Isso é chamado de "autenticação mútua".

A geração de certificado e importação começa ao considerar uma autoriade de certificação confiável(CA).

## Certificate authority (CA)

Para poder assinar os certificados do lado do servidor e do lado do cliente, precisamos primeiro criar nosso próprio certificado raiz de autoridade de certificação autoassinado. Dessa forma, agiremos como nossa própria autoridade de certificação. A criação ocorre através do seguinte comando:

>openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt

- **openssl**: Esta é a ferramenta de linha de comando do OpenSSL.

- **req**: Este subcomando é usado para solicitações de certificados X.509 e funções relacionadas.

- **x509**: Esta opção especifica que um certificado autoassinado está sendo criado.

- **sha256**: Esta opção especifica o algoritmo de hash a ser usado, neste caso, SHA-256.

- **days 3650**: Isso define o período de validade do certificado para 3650 dias (aproximadamente 10 anos).

- **newkey rsa:4096**: Isso gera uma nova chave privada RSA com um comprimento de chave de 4096 bits.

- **keyout rootCA.key**: Isso especifica o arquivo onde a chave privada gerada será salva.

- **out rootCA.crt**: Isso especifica o arquivo onde o certificado X.509 gerado será salvo.

Em resumo, este comando gera um certificado raiz autoassinado com uma chave privada RSA de 4096 bits, usando o algoritmo de hash SHA-256, e define sua validade para 10 anos. A chave privada é salva em um arquivo chamado rootCA.key, e o certificado X.509 é salvo em um arquivo chamado rootCA.crt.

## Keystore
Criação de um "keystore". Definição: (armazenamento de chaves) é um repositório seguro utilizado para armazenar chaves criptográficas, certificados digitais e, em alguns casos, segredos criptograficamente sensíveis. No nosso caso é um repositório de chave privada, a chave privada do nosso servidor.

### Criando certificado server-side

> openssl req -new -newkey rsa:4096 -keyout localhost.key -out localhost.csr

O comando acima utiliza o OpenSSL para criar uma solicitação de assinatura de certificado (CSR) e uma nova chave privada RSA. Vamos analisar o comando passo a passo:

- **openssl**: A ferramenta de linha de comando OpenSSL.

- **req**: Subcomando usado para gerar e processar solicitações de certificado X.509.

- **new**: Indica que uma nova CSR será gerada.

- **newkey rsa:4096**: Gera uma nova chave privada RSA com um comprimento de 4096 bits.

- **keyout localhost.key**: Especifica o arquivo onde a nova chave privada será salva. Neste caso, ela é salva como "localhost.key".

- **out localhost.csr**: Especifica o arquivo onde a CSR será salva. Neste caso, ela é salva como "localhost.csr".

É necessário um arquivo (localhost.ext) de configuração externo com o seguinte conteúdo:

><p> authorityKeyIdentifier=keyid,issuer<p>
><p> basicConstraints=CA:FALSE<p>
><p> subjectAltName = @alt_names<p>
><p>[alt_names]<p>
><p> DNS.1 = localhost<p>

Assine o request com o nosso CA:

>openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in localhost.csr -out localhost.crt -days 365 -CAcreateserial -extfile localhost.ext


Este comando OpenSSL está sendo utilizado para assinar uma solicitação de certificado (CSR) com a chave privada de uma Autoridade Certificadora (CA), gerando assim um certificado X.509 para um servidor. Aqui está uma explicação dos parâmetros utilizados:

- **openssl**: A ferramenta de linha de comando OpenSSL.

- **x509**: Subcomando utilizado para manipular certificados X.509.

- **req**: Indica que a entrada é uma CSR (solicitação de certificado).

- **CA rootCA.crt**: Especifica o certificado da Autoridade Certificadora (CA) que será usado para assinar a CSR.

- **CAkey rootCA.key**: Especifica a chave privada da CA que será usada para assinar a CSR.

- **in localhost.csr**: Especifica o arquivo contendo a CSR que será assinada.

- **out localhost.crt**: Especifica o arquivo de saída onde o certificado assinado será salvo.

- **days 365**: Define a validade do certificado para 365 dias.

- **CAcreateserial**: Cria um arquivo serial para acompanhar os números de série dos certificados assinados pela CA.

- **extfile localhost.ext**: Especifica um arquivo de configuração contendo extensões adicionais para serem incluídas no certificado. Essas extensões podem incluir informações como alternativas de nome do domínio (SANs) e outras configurações específicas.

### Importando certificado server-side e criando keystore

Primeiramente temos que empacotar nossa chave primária com o certificado, usamos o comando abaixo:

>openssl pkcs12 -export -out localhost.p12 -name "localhost" -inkey localhost.key -in localhost.crt


- **openssl**: A ferramenta de linha de comando OpenSSL.

- **pkcs12**: Subcomando usado para manipular arquivos no formato PKCS#12.

- **export**: Indica que você deseja criar um arquivo PKCS#12.

- **out localhost.p12**: Especifica o nome do arquivo de saída, que será um arquivo PKCS#12. Neste caso, é "localhost.p12".

- **name "localhost"**: Especifica o nome do "objeto amigável" (friendly name) que será associado ao certificado dentro do arquivo PKCS#12.

- **inkey localhost.key**: Especifica o arquivo contendo a chave privada associada ao certificado.

- **in localhost.crt**: Especifica o arquivo contendo o certificado.

Agora criamos nosso keystore, junto com o nosso .p12

>keytool -importkeystore -srckeystore localhost.p12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype JKS

- **keytool**: Uma ferramenta de linha de comando que faz parte do kit de ferramentas do Java (Java Development Kit - JDK), utilizada para gerenciar certificados, chaves e keystores.

- **importkeystore**: Este subcomando especifica que você deseja importar um keystore.

- **srckeystore localhost.p12**: Especifica o keystore de origem, que neste caso é o arquivo "localhost.p12".

- **srcstoretype PKCS12**: Indica o tipo de keystore de origem, que é PKCS#12. Isso é necessário porque o formato do keystore de origem é diferente do formato padrão do Java KeyStore (JKS).

- **destkeystore keystore.jks**: Especifica o keystore de destino, que será criado com o nome "keystore.jks". Este é um keystore no formato Java KeyStore (JKS).

- **deststoretype JKS**: Indica o tipo de keystore de destino, que é JKS.

## Truststore
De maneira simplificada é um Keystore de Chave Pública.Possui a finalidade de Armazenar certificados de entidades confiáveis.

### Criando TrustStore e inserindo o nosso CA

>keytool -import -trustcacerts -noprompt -alias ca -ext san=dns:localhost,ip:127.0.0.1 -file rootCA.crt -keystore truststore.jks


- **keytool**: A ferramenta de linha de comando do Java para gerenciar certificados, chaves e keystores.

- **import**: Especifica que você deseja importar um certificado.

- **trustcacerts**: Indica que o certificado a ser importado deve ser tratado como uma CA, ou seja, um certificado de autoridade de certificação.

- **noprompt**: Esta opção indica que o comando não deve solicitar confirmação do usuário antes de executar a operação.

- **alias ca**: Define um alias (apelido) para o certificado que está sendo importado. Neste caso, o alias é definido como "ca".

- **ext san=dns**:localhost,ip:127.0.0.1: Esta opção é utilizada para adicionar extensões ao certificado importado. No caso, são especificadas alternativas de nome do assunto (Subject Alternative Name - SAN) contendo o DNS "localhost" e o endereço IP "127.0.0.1".

- **file rootCA.crt**: Especifica o arquivo que contém o certificado a ser importado, que neste caso é "rootCA.crt".

- **keystore truststore.jks**: Especifica o truststore de destino, onde o certificado será importado. Neste caso, o truststore é salvo como "truststore.jks".


## Certificado Client-side
Cria-se o certificado com o comando já utilizado anteriormente
>openssl req -new -newkey rsa:4096 -nodes -keyout teste.key -out teste.csr

Assina-se o certificado com nosso root CA através do também já apresentado comando:

>openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in clientBob.csr -out clientBob.crt -days 365 -CAcreateserial

## Considerações finais
Com os certificados devidamente assinados pelo rootCa, os arquivos keystore e truststore estarão devidamente populados e podem ser usador na aplicação
se enviados através das variáveis TRUST_STORE_PATH/TRUST_STORE_PASSWORD e KEY_STORE_PATH/KEY_STORE_PASSWORD.
Caso prefira, o protótipo já possui arquivos padrões.
