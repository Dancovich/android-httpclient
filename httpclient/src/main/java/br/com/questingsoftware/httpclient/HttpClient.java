package br.com.questingsoftware.httpclient;

import android.os.AsyncTask;
import android.os.Build;
import android.support.annotation.Nullable;
import android.support.v4.os.AsyncTaskCompat;
import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * <p>Classe simples de conexão HTTP. Essa classe estabelece uma conexão usando o método solicitado,
 * opcionalmente faz upload dos dados (o encoding desses dados deve ser informado via atributo
 * no cabeçalho) e obtem o código, cabeçalho e dados do retorno.</p>
 * <p/>
 * <p>A conexão é feita em uma thread separada. Para ser informado do término da operação, implemente
 * a interface {@link HttpClientCallback} e passe uma instância dessa implementação no método "doRequest"
 * para solicitar que esse callback seja chamado ao término da operação.</p>
 *
 * @author Danilo Costa Viana
 */
@SuppressWarnings("unused")
public class HttpClient<CP> {

    private static final String LOG_TAG = "HttpClient";

    /**
     * Indica que o cliente fechou a conexão pematuramente.
     */
    public static final int HTTP_CLIENT_CLOSED = 499;

    /**
     * Indica que essa instância de HttpClient falhou em criar
     * o recurso de conexão remota.
     */
    public static final int HTTP_INTERNAL_CLIENT_ERROR = 599;

    private SSLContext context;

    private int connectionTimeoutInMillis = 30000;

    private int readTimeoutInMillis = 60000;

    private int bufferSize = 1024;

    private final HashMap<Integer, AsyncTaskStore> connectionTaskCache = new HashMap<>();

    public HttpClientCallback<CP> getCallback(final int requestId) {
        AsyncTaskStore store = connectionTaskCache.get(requestId);
        if (store != null) {
            return store.callback;
        }

        return null;
    }

    /**
     * @see #setConnectionTimeoutInMillis(int)
     */
    public int getConnectionTimeoutInMillis() {
        return connectionTimeoutInMillis;
    }

    /**
     * @param connectionTimeoutInMillis Timeout para estabelecer uma conexão com o host remoto.
     */
    public void setConnectionTimeoutInMillis(int connectionTimeoutInMillis) {
        this.connectionTimeoutInMillis = connectionTimeoutInMillis;
    }

    /**
     * @see #setReadTimeoutInMillis(int)
     */
    public int getReadTimeoutInMillis() {
        return readTimeoutInMillis;
    }

    /**
     * @param readTimeoutInMillis Timeout para receber a resposta do servidor (incluindo download de corpo da resposta).
     */
    public void setReadTimeoutInMillis(int readTimeoutInMillis) {
        this.readTimeoutInMillis = readTimeoutInMillis;
    }

    /**
     * @see #setBufferSize(int)
     */
    public int getBufferSize() {
        return bufferSize;
    }

    /**
     * @param bufferSize Define o tamanho do buffer de transferência do corpo das requisições.
     *                   O método {@link HttpClientCallback#onConnectionProgress(int, long
     *, long, long, Object)} também será chamado toda vez que essa quantidade
     *                   de bytes for transferida. O padrão é 1024.
     */
    public void setBufferSize(int bufferSize) {
        if (bufferSize > 0) {
            this.bufferSize = bufferSize;
        }
    }

    /**
     * Define um certificado personalizado para confiar durante conexões. Conexões HTTPS
     * feitas após definir essa cadeia o usarão para confiar em servidores
     * remotos seguros.
     */
    public void setCustomTrustCertificate(InputStream certificateInputStream) {
        Log.d(LOG_TAG, "Definindo corrente de certificados confiáveis personalizada");

        // Carrega o arquivo informado como um certificado
        Certificate ca;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ca = cf.generateCertificate(certificateInputStream);
            Log.d(HttpClient.class.getSimpleName(), "ca=" + ((X509Certificate) ca).getSubjectDN());
        } catch (CertificateException e) {
            e.printStackTrace();
            ca = null;
        } finally {
            try {
                certificateInputStream.close();
            } catch (IOException ignored) {
                //NOOP
            }
        }

        // Cria uma keystore contendo nosso certificado
        KeyStore keyStore = null;
        if (ca != null) {
            try {
                String keyStoreType = KeyStore.getDefaultType();
                keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(null, null);
                keyStore.setCertificateEntry("ca", ca);
            } catch (Exception e) {
                Log.e(HttpClient.class.getSimpleName(), "Erro criando keystore a partir do certificado informado", e);
                keyStore = null;
            }
        }

        // Cria um gestor de confiança que confia em nossa keystore
        TrustManagerFactory tmf = null;
        if (keyStore != null) {
            try {
                String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
                tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
                tmf.init(keyStore);
            } catch (Exception e) {
                Log.e(HttpClient.class.getSimpleName(), "Erro criando gestor de confiança a partir do certificado informado", e);
                tmf = null;
            }
        }

        // Cria um contexto SSL. A partir daqui podemos fabricar sockets seguros
        // que confiam no certificado carregado.
        SSLContext context = null;
        if (tmf != null) {
            try {
                context = SSLContext.getInstance("TLS");
                context.init(null, tmf.getTrustManagers(), null);
            } catch (Exception e) {
                Log.e(HttpClient.class.getSimpleName(), "Erro criando contexto SSL a partir do certificado informado", e);
                context = null;
            }
        }

        this.context = context;
    }

    /**
     * Limpa o certificado previamente definido
     * com {@link #setCustomTrustCertificate(InputStream)}. Conexões
     * passarão a confiar apenas na cadeia padrão do dispositivo.
     */
    public void clearTrustChainKeystore() {
        this.context = null;
    }

    /**
     * @throws MalformedURLException Se a String informada não contém uma URL bem formada.
     * @see HttpClient#doRequest(int requestId, HttpClientCallback callback, URL url, String method, Map header, InputStream uploadData, OutputStream payloadOutputStream, Object clientParam)
     */
    public void doRequest(final int requestId, final HttpClientCallback<CP> callback, String url
            , String method, @Nullable Map<String, String> header
            , @Nullable InputStream uploadData, final OutputStream payloadOutputStream
            , @Nullable final CP clientParam) throws MalformedURLException {
        URL urlAddress = new URL(url);
        doRequest(requestId, callback, urlAddress, method, header, uploadData, payloadOutputStream, clientParam);
    }

    /**
     * <p>Estabelece uma conexão com a URL informada e retorna o resultado.</p>
     * <p/>
     * <p>Essa operação deve ser chamada na thread de UI. Ela é assíncrona e esse método retorna imediatamente.
     * Se for informado um {@link HttpClientCallback} então os métodos
     * {@link HttpClientCallback#onContentReceived(int, ResultStore, Object)},
     * {@link HttpClientCallback#onConnectionProgress(int, long, long, long, Object)} e
     * {@link HttpClientCallback#onConnectionCanceled(int, ResultStore, Object)} serão
     * chamados na thread de UI durante as fases equivalentes da requisição.</p>
     * <p/>
     * <p>Lembre-se que esse método não chama {@link OutputStream#close()}
     * em <code>downloadBody</code>, se esse stream precisa ser fechado faça-o em
     * {@link HttpClientCallback#onContentReceived(int requestId, ResultStore result, Object clientParam)}.</p>
     *
     * @param requestId    ID único que será passado para os métodos contidos em {@link HttpClientCallback}
     *                     para identificar a origem da chamada ao método de callback.
     * @param callback     Objeto que, ao final da conexão terá seu método {@link HttpClientCallback#onContentReceived(int requestId, ResultStore result, Object clientParams)}
     *                     chamado com o retorno do servidor, representado pelo objeto {@link ResultStore}.
     * @param url          Endereço a se conectar.
     * @param method       Método HTTP que deve ser usado para conectar-se.
     * @param header       Atributos a serem informados no cabeçalho da requisição.
     * @param uploadBody   O método lerá dados desse input stream e os enviará ao servidor como corpo da requisição. Se for
     *                     nulo nenhum corpo será enviado.
     * @param downloadBody O método lerá o corpo da resposta do servidor e escreverá esses dados nesse output stream. Se for
     *                     nulo o corpo da resposta será ignorado. Se não houver corpo na resposta nada será escrito nesse stream.
     * @param clientParam  Se um callback for definido, após
     *                     a conclusão da requisição esses parâmetros serão repassados na chamada a
     *                     {@link HttpClientCallback#onContentReceived(int requestId, ResultStore result, Object clientParam)}
     *                     no argumento <code>clientParam</code>
     */
    public void doRequest(final int requestId, @Nullable final HttpClientCallback<CP> callback
            , final URL url, final String method, @Nullable Map<String, String> header
            , @Nullable final InputStream uploadBody
            , @Nullable final OutputStream downloadBody, @Nullable final CP clientParam) {

        disableConnectionReuseIfNecessary();

        cancelRequest(requestId);

        AsyncTask<Object, Long, ResultStore> newTask = new AsyncTask<Object, Long, ResultStore>() {

            final SSLContext sslContext = HttpClient.this.context;

            private HttpClientCallback<CP> callback;

            private CP clientParam;

            @SuppressWarnings({"unchecked", "ConstantConditions"})
            @Override
            protected ResultStore doInBackground(Object... params) {
                long bytesSent = 0L;
                long bytesRead = 0L;
                long totalBytesToRead = 0L;
                final byte[] buffer = new byte[bufferSize];
                int qtdBytesBuffered;

                final String requestMethod = (String) params[0];
                final Map<String, String> requestHeader = (Map) params[1];
                final InputStream dataToUpload = (InputStream) params[2];
                final OutputStream payloadOutputStream = (OutputStream) params[3];
                callback = (HttpClientCallback) params[4];
                clientParam = (CP) params[5];
                final URL url = (URL) params[6];


                ResultStore result = new ResultStore(payloadOutputStream);

                HttpURLConnection conn;
                try {
                    conn = (HttpURLConnection) url.openConnection();

                    // Se foi definido um certificado de confiança, usa-o para criar a conexão.
                    if (sslContext != null && HttpsURLConnection.class.isInstance(conn)) {
                        ((HttpsURLConnection) conn).setSSLSocketFactory(sslContext.getSocketFactory());
                    }

                    Log.d(LOG_TAG, "Conexão aberta");
                } catch (IOException e) {
                    conn = null;
                    Log.w(LOG_TAG, "Conexão não pôde ser aberta", e);
                }

                if (conn == null) {
                    result.statusCode = HTTP_INTERNAL_CLIENT_ERROR;

                    if (result.getResponseBody() != null) {
                        InputStream is = IOUtil.createStream("Não foi possível criar conexão.");

                        try {
                            while ((qtdBytesBuffered = is.read(buffer)) != -1) {
                                result.getResponseBody().write(buffer, 0, qtdBytesBuffered);
                            }
                        } catch (IOException ioe) {
                            ioe.printStackTrace();
                        }
                    }

                    return result;
                }

                try {
                    conn.setAllowUserInteraction(false);
                    conn.setConnectTimeout(connectionTimeoutInMillis);
                    conn.setReadTimeout(readTimeoutInMillis);
                    conn.setRequestMethod(method);
                    conn.setChunkedStreamingMode(0);

                    if (requestHeader != null) {
                        for (String key : requestHeader.keySet()) {
                            conn.addRequestProperty(key, requestHeader.get(key));
                        }
                    }

                    if (dataToUpload != null && !isCancelled()) {
                        Log.d(LOG_TAG, "Enviando corpo da requisição");

                        conn.setDoOutput(true);
                        OutputStream os = new BufferedOutputStream(conn.getOutputStream());
                        while (!isCancelled() && (qtdBytesBuffered = dataToUpload.read(buffer)) != -1) {
                            os.write(buffer, 0, qtdBytesBuffered);

                            bytesSent += qtdBytesBuffered;
                            publishProgress(bytesSent, bytesRead, totalBytesToRead);
                            Log.d(LOG_TAG, "enviando...");
                        }

                        os.close();
                    }

                    if (!isCancelled()) {
                        result.statusCode = conn.getResponseCode();
                        result.returnHeader = conn.getHeaderFields();

                        if (result.returnHeader != null) {
                            List<String> contentLengthValues = result.returnHeader.get("Content-Length");
                            if (contentLengthValues == null) {
                                contentLengthValues = result.returnHeader.get("content-length");
                            }
                            if (contentLengthValues == null) {
                                contentLengthValues = result.returnHeader.get("CONTENT-LENGTH");
                            }

                            if (contentLengthValues != null && !contentLengthValues.isEmpty()) {
                                try {
                                    long contentLength = Long.parseLong(contentLengthValues.get(0));
                                    totalBytesToRead += contentLength;
                                } catch (NumberFormatException ignored) {
                                    //NOOP
                                }
                            }
                        }

                        if (result.getResponseBody() != null) {
                            InputStream contentInputStream = conn.getInputStream();

                            if (contentInputStream != null) {
                                Log.d(LOG_TAG, "Recebendo resposta do servidor");

                                while (!isCancelled() && (qtdBytesBuffered = contentInputStream.read(buffer)) != -1) {
                                    result.getResponseBody().write(buffer, 0, qtdBytesBuffered);

                                    bytesRead += qtdBytesBuffered;

                                    if (bytesRead % bufferSize == 0) {
                                        publishProgress(bytesSent, bytesRead, totalBytesToRead);
                                        Log.d(LOG_TAG, "recebendo...");
                                    }
                                }

                                contentInputStream.close();

                                if (isCancelled()) {
                                    result.statusCode = HTTP_CLIENT_CLOSED;
                                    result.returnHeader = null;
                                    Log.d(LOG_TAG, "Conexão cancelada");
                                }
                            }
                        }
                    } else {
                        result.statusCode = HTTP_CLIENT_CLOSED;
                        result.returnHeader = null;
                        Log.d(LOG_TAG, "Conexão cancelada");
                    }

                    return result;
                } catch (ProtocolException e) {
                    result.statusCode = HTTP_INTERNAL_CLIENT_ERROR;

                    if (result.getResponseBody() != null) {
                        InputStream is = IOUtil.createStream("Protocolo inválido: '" + requestMethod + "'.");

                        try {
                            while ((qtdBytesBuffered = is.read(buffer)) != -1) {
                                result.getResponseBody().write(buffer, 0, qtdBytesBuffered);
                            }
                        } catch (IOException ioe) {
                            Log.e(LOG_TAG, "Protocolo inválido", ioe);
                        }
                    }

                    return result;
                } catch (IOException e) {

                    if (result.getResponseBody() != null) {
                        InputStream errorInputStream = conn.getErrorStream();
                        if (errorInputStream != null) {
                            try {
                                while ((qtdBytesBuffered = errorInputStream.read(buffer)) != -1) {
                                    result.getResponseBody().write(buffer, 0, qtdBytesBuffered);
                                }

                                errorInputStream.close();
                            } catch (IOException secondIOE) {
                                Log.e(LOG_TAG, "Erro de IO", secondIOE);
                            }
                        }
                    }

                    return result;
                } finally {
                    conn.disconnect();
                }
            }

            @Override
            protected void onProgressUpdate(Long... values) {
                if (callback != null) {
                    callback.onConnectionProgress(requestId
                            , values[0]
                            , values[1]
                            , values[2]
                            , clientParam);
                }
            }

            @Override
            protected void onPostExecute(ResultStore result) {
                if (callback != null) {
                    callback.onContentReceived(requestId, result, clientParam);
                }
            }

            @Override
            protected void onCancelled(ResultStore result) {
                if (callback != null) {
                    callback.onConnectionCanceled(requestId, result, clientParam);
                }
            }
        };

        AsyncTaskStore store = new AsyncTaskStore();
        store.asyncTask = newTask;
        store.callback = callback;

        AsyncTaskCompat.executeParallel(newTask, method, header, uploadBody, downloadBody, callback, clientParam, url);
        //newTask.execute(method, header, uploadBody, downloadBody, callback, clientParam);
        connectionTaskCache.put(requestId, store);
    }

    /**
     * Se existe uma conexão sendo executada no ID informado, cancela
     * essa requisição.
     *
     * @param requestId ID da requisição solicitada.
     */
    public void cancelRequest(final int requestId) {
        final AsyncTaskStore store = connectionTaskCache.get(requestId);
        if (store != null
                && store.asyncTask != null
                && store.asyncTask.getStatus() != AsyncTask.Status.FINISHED) {
            store.asyncTask.cancel(false);
        }

        //noinspection SuspiciousMethodCalls
        connectionTaskCache.remove(store);
    }

    /*
    Informa se existe uma requisição executando no ID informado.
     */
    public boolean isRequestRunning(final int requestId) {
        final AsyncTaskStore store = connectionTaskCache.get(requestId);
        return store != null
                && store.asyncTask != null
                && store.asyncTask.getStatus() != AsyncTask.Status.FINISHED;
    }

    private static void disableConnectionReuseIfNecessary() {
        // see HttpURLConnection API doc
        if (Build.VERSION.SDK_INT
                < Build.VERSION_CODES.FROYO) {
            System.setProperty("http.keepAlive", "false");
        }
    }

    private class AsyncTaskStore {
        AsyncTask<Object, Long, ResultStore> asyncTask;
        HttpClientCallback<CP> callback;
    }

    /**
     * Classe de callback onde serão escritos os dados
     * de retorno do resultado da conexão.
     */
    public static class ResultStore {
        private int statusCode;
        private Map<String, List<String>> returnHeader;
        private final OutputStream content;

        /**
         * @param contentOutputStream OutputStream onde será escrito o payload do retorno
         *                            do servidor. Não pode ser <code>null</code> mas se não houver
         *                            payload de retorno nada será escrito no OutputStream.
         */
        public ResultStore(OutputStream contentOutputStream) {
            this.content = contentOutputStream;
        }


        /**
         * @return Código HTTP de retorno do servidor.
         */
        public int getStatusCode() {
            return statusCode;
        }

        /**
         * @return Map contendo o cabeçalho de resposta do servidor.
         */
        public Map<String, List<String>> getReturnHeader() {
            return returnHeader;
        }

        /**
         * @return O mesmo OutputStream passado como parâmetro em
         * {@link ResultStore#ResultStore(OutputStream)}.
         * Após o retorno do servidor qualquer dado contido no payload de resposta será escrito aqui.
         */
        public OutputStream getResponseBody() {
            return content;
        }
    }

    /**
     * Classes que desejam ser notificadas quando o servidor
     * remoto responder à requisição devem implementar essa interface.
     */
    public interface HttpClientCallback<CP> {

        /**
         * Chamado quando o servidor remoto responde à requisição.
         *
         * @param requestId     ID passado para {@link HttpClient#doRequest(int requestId
         *, HttpClientCallback callback, URL url, String method, Map header
         *, InputStream uploadData, OutputStream payloadOutputStream
         *, Object clientParams)}
         *                      como primeiro argumento e usado para identificar que tentativa de conexão retornou esse resultado.
         * @param requestResult Contém dados da resposta do servidor como o código
         *                      HTTP, o cabeçalho de resposta e um OutputStream onde
         *                      o corpo da mensagem (se houver) foi escrito.
         * @param clientParam   Parâmetro passado em {@link HttpClient#doRequest(int requestId
         *, HttpClientCallback callback, URL url, String method, Map header
         *, InputStream uploadBody, OutputStream downloadBody, Object clientParam)}
         *                      será diretamente recebido aqui, sem transformações.
         */
        void onContentReceived(int requestId, ResultStore requestResult, CP clientParam);

        /**
         * @param requestId     ID passado para {@link #doRequest(int, HttpClientCallback, URL, String, Map, InputStream, OutputStream, Object)}
         *                      como primeiro argumento e usado para identificar que tentativa de conexão foi cancelada.
         * @param requestResult Contém dados da resposta do servidor como o código
         *                      HTTP. O status de uma conexão cancelada será sempre {@link #HTTP_CLIENT_CLOSED}.
         * @param clientParam   Parâmetro passado em {@link HttpClient#doRequest(int requestId, HttpClientCallback callback, URL url, String method, Map header, InputStream uploadBody, OutputStream downloadBody, Object clientParam)}
         *                      será diretamente recebido aqui, sem transformações.
         */
        void onConnectionCanceled(int requestId, ResultStore requestResult, CP clientParam);

        /**
         * @param requestId        ID passado para {@link #doRequest(int, HttpClientCallback, URL
         *, String, Map, InputStream, OutputStream, Object)}
         *                         como primeiro argumento e usado para identificar qual conexão
         *                         está tendo seu progresso atualizado.
         * @param bytesSent        Quantos bytes já foram enviados, caso um corpo para envio seja
         *                         fornecido. Caso não haja corpo para envio esse valor será sempre 0.
         * @param bytesRead        Quantos bytes já foram lidos da resposta do servidor.
         *                         Apenas o corpo é considerado, requisições que não retornam corpo
         *                         sempre reportarão 0 aqui.
         * @param bytesTotalToRead Total de bytes a ler do corpo. O servidor precisa informar esse
         *                         valor, do contrário será sempre 0.
         * @param clientParam      Parâmetro passado em {@link HttpClient#doRequest(int requestId
         *, HttpClientCallback callback, URL url, String method, Map header
         *, InputStream uploadBody, OutputStream downloadBody, Object clientParam)}
         *                         será diretamente recebido aqui, sem transformações.
         */
        void onConnectionProgress(int requestId, long bytesSent, long bytesRead, long bytesTotalToRead, CP clientParam);
    }
}