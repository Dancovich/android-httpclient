package br.com.questingsoftware.httpclient;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Scanner;

public class IOUtil {

    /**
     * Lê todo o conteúdo de um InputStream e retorna o resultado como uma String.
     *
     * @param is InputStream de onde ler caracteres
     * @return A String lida do InputStream
     */
    public static String extractStringFromStream(InputStream is) {
        return new Scanner(is).useDelimiter("\\A").next();
    }

    public static InputStream createStream(String string) {
        return new ByteArrayInputStream(Charset.forName("UTF-8").encode(string).array());
    }


}