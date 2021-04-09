package org.wso2.carbon.identity.extension.authz.rest.selfservice.wrapper;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;

/**
 * A custom wrapper for the HTTPServletRequest to read the request body.
 */
public class SelfServiceAuthzHTTPServletRequestWrapper extends HttpServletRequestWrapper {

    private static final Log log = LogFactory.getLog(SelfServiceAuthzHTTPServletRequestWrapper.class);

    private byte[] bytes;

    public SelfServiceAuthzHTTPServletRequestWrapper(HttpServletRequest request) throws IOException {

        super(request);
        bytes = IOUtils.toByteArray(request.getInputStream());
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {

        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ServletInputStream servletInputStream = new ServletInputStream() {
            public boolean isFinished() {
                return byteArrayInputStream.available() == 0;
            }

            public boolean isReady() {
                return true;
            }

            public void setReadListener(ReadListener listener) {
                System.out.println("Listener ");
            }
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }
        };
        return servletInputStream;
    }

    @Override
    public BufferedReader getReader() throws IOException {

        return new BufferedReader(new InputStreamReader(getInputStream()));
    }

    public String getBody() throws IOException {

        return IOUtils.toString(getReader());
    }
}
