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
 * Custom request wrapper to read the request body.
 *
 * @author asela@wso2.com
 */
public class SelfServiceAuthzHTTPServletRequestWrapper extends HttpServletRequestWrapper {

    private static final Log log = LogFactory.getLog(SelfServiceAuthzHTTPServletRequestWrapper.class);

    private byte[] rawData;
    private final HttpServletRequest request;
    private final ResettableServletInputStream servletStream;

    public SelfServiceAuthzHTTPServletRequestWrapper(HttpServletRequest request) {

        super(request);
        this.request = request;
        this.servletStream = new ResettableServletInputStream();
    }

    public void resetInputStream() {

        servletStream.stream = new ByteArrayInputStream(rawData);
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {

        if (rawData == null) {
            rawData = IOUtils.toByteArray(this.request.getReader());
            servletStream.stream = new ByteArrayInputStream(rawData);
        }
        return servletStream;
    }

    @Override
    public BufferedReader getReader() throws IOException {

        if (rawData == null) {
            rawData = IOUtils.toByteArray(this.request.getReader());
            servletStream.stream = new ByteArrayInputStream(rawData);
        }
        return new BufferedReader(new InputStreamReader(servletStream));
    }

    private class ResettableServletInputStream extends ServletInputStream {

        private InputStream stream;

        @Override
        public int read() throws IOException {

            return stream.read();
        }

        @Override
        public boolean isFinished() {

            return false;
        }

        @Override
        public boolean isReady() {

            return false;
        }

        @Override
        public void setReadListener(ReadListener readListener) {

        }
    }
}
