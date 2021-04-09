package org.wso2.carbon.identity.extension.authz.rest.selfservice.wrapper;

import org.apache.catalina.Context;
import org.apache.catalina.Host;
import org.apache.catalina.Session;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.AsyncContextImpl;
import org.apache.catalina.mapper.MappingData;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.ServerCookies;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

/**
 * A custom wrapper for the Catalina request to read the request body.
 */
public class SelfServiceAuthzCatalinaRequestWrapper extends Request {

    private final Request request;

    public SelfServiceAuthzCatalinaRequestWrapper(Request request) throws IOException {

        super(request.getConnector());
        this.request = request;
        this.request.setRequest(new SelfServiceAuthzHTTPServletRequestWrapper(request.getRequest()));
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {

        ServletInputStream servletInputStream = this.request.getRequest().getInputStream();
        return servletInputStream;
    }

    @Override
    public BufferedReader getReader() throws IOException {

        return new BufferedReader(new InputStreamReader(this.getInputStream()));
    }

    @Override
    public org.apache.coyote.Request getCoyoteRequest() {

        return this.request.getCoyoteRequest();
    }

    @Override
    public void setCoyoteRequest(org.apache.coyote.Request coyoteRequest) {

        this.request.setCoyoteRequest(coyoteRequest);
    }

    @Override
    public void recycle() {

        this.request.recycle();
    }

    @Override
    public Connector getConnector() {

        return this.request.getConnector();
    }

    @Override
    public Context getContext() {

        return this.request.getContext();
    }

    @Override
    public boolean getDiscardFacades() {

        return this.request.getDiscardFacades();
    }

    @Override
    public FilterChain getFilterChain() {

        return this.request.getFilterChain();
    }

    @Override
    public void setFilterChain(FilterChain filterChain) {

        this.request.setFilterChain(filterChain);
    }

    @Override
    public Host getHost() {

        return this.request.getHost();
    }

    @Override
    public MappingData getMappingData() {

        return this.request.getMappingData();
    }

    @Override
    public HttpServletRequest getRequest() {

        return this.request.getRequest();
    }

    @Override
    public void setRequest(HttpServletRequest applicationRequest) {

        this.request.setRequest(applicationRequest);
    }

    @Override
    public Response getResponse() {

        return this.request.getResponse();
    }

    @Override
    public void setResponse(Response response) {

        this.request.setResponse(response);
    }

    @Override
    public InputStream getStream() {

        return this.request.getStream();
    }

    @Override
    public Wrapper getWrapper() {

        return this.request.getWrapper();
    }

    @Override
    public ServletInputStream createInputStream() throws IOException {

        return this.request.createInputStream();
    }

    @Override
    public void finishRequest() throws IOException {

        this.request.finishRequest();
    }

    @Override
    public Object getNote(String name) {

        return this.request.getNote(name);
    }

    @Override
    public void removeNote(String name) {

        this.request.removeNote(name);
    }

    @Override
    public void setNote(String name, Object value) {

        this.request.setNote(name, value);
    }

    @Override
    public Object getAttribute(String name) {

        return this.request.getAttribute(name);
    }

    @Override
    public long getContentLengthLong() {

        return this.request.getContentLengthLong();
    }

    @Override
    public Enumeration<String> getAttributeNames() {

        return this.request.getAttributeNames();
    }

    @Override
    public String getCharacterEncoding() {

        return this.request.getCharacterEncoding();
    }

    @Override
    public void setCharacterEncoding(String enc) throws UnsupportedEncodingException {

        this.request.setCharacterEncoding(enc);
    }

    @Override
    public int getContentLength() {

        return this.request.getContentLength();
    }

    @Override
    public String getContentType() {

        return this.request.getContentType();
    }

    @Override
    public void setContentType(String contentType) {

        this.request.setContentType(contentType);
    }

    @Override
    public Locale getLocale() {

        return this.request.getLocale();
    }

    @Override
    public Enumeration<Locale> getLocales() {

        return this.request.getLocales();
    }

    @Override
    public String getParameter(String name) {

        return this.request.getParameter(name);
    }

    @Override
    public Map<String, String[]> getParameterMap() {

        return this.request.getParameterMap();
    }

    @Override
    public Enumeration<String> getParameterNames() {

        return this.request.getParameterNames();
    }

    @Override
    public String[] getParameterValues(String name) {

        return this.request.getParameterValues(name);
    }

    @Override
    public String getProtocol() {

        return this.request.getProtocol();
    }

    @Override
    public String getRealPath(String path) {

        return this.request.getRealPath(path);
    }

    @Override
    public String getRemoteAddr() {

        return this.request.getRemoteAddr();
    }

    @Override
    public void setRemoteAddr(String remoteAddr) {

        this.request.setRemoteAddr(remoteAddr);
    }

    @Override
    public String getRemoteHost() {

        return this.request.getRemoteHost();
    }

    @Override
    public void setRemoteHost(String remoteHost) {

        this.request.setRemoteHost(remoteHost);
    }

    @Override
    public int getRemotePort() {

        return this.request.getRemotePort();
    }

    @Override
    public String getLocalName() {

        return this.request.getLocalName();
    }

    @Override
    public String getLocalAddr() {

        return this.request.getLocalAddr();
    }

    @Override
    public int getLocalPort() {

        return this.request.getLocalPort();
    }

    @Override
    public void setLocalPort(int port) {

        this.request.setLocalPort(port);
    }

    @Override
    public RequestDispatcher getRequestDispatcher(String path) {

        return this.request.getRequestDispatcher(path);
    }

    @Override
    public String getScheme() {

        return this.request.getScheme();
    }

    @Override
    public String getServerName() {

        return this.request.getServerName();
    }

    @Override
    public int getServerPort() {

        return this.request.getServerPort();
    }

    @Override
    public void setServerPort(int port) {

        this.request.setServerPort(port);
    }

    @Override
    public boolean isSecure() {

        return this.request.isSecure();
    }

    @Override
    public void setSecure(boolean secure) {

        this.request.setSecure(secure);
    }

    @Override
    public void removeAttribute(String name) {

        this.request.removeAttribute(name);
    }

    @Override
    public void setAttribute(String name, Object value) {

        this.request.setAttribute(name, value);
    }

    @Override
    public ServletContext getServletContext() {

        return this.request.getServletContext();
    }

    @Override
    public AsyncContext startAsync() {

        return this.request.startAsync();
    }

    @Override
    public AsyncContext startAsync(ServletRequest request, ServletResponse response) {

        return this.request.startAsync(request, response);
    }

    @Override
    public boolean isAsyncStarted() {

        return this.request.isAsyncStarted();
    }

    @Override
    public boolean isAsyncDispatching() {

        return this.request.isAsyncDispatching();
    }

    @Override
    public boolean isAsyncCompleting() {

        return this.request.isAsyncCompleting();
    }

    @Override
    public boolean isAsync() {

        return this.request.isAsync();
    }

    @Override
    public boolean isAsyncSupported() {

        return this.request.isAsyncSupported();
    }

    @Override
    public void setAsyncSupported(boolean asyncSupported) {

        this.request.setAsyncSupported(asyncSupported);
    }

    @Override
    public AsyncContext getAsyncContext() {

        return this.request.getAsyncContext();
    }

    @Override
    public AsyncContextImpl getAsyncContextInternal() {

        return this.request.getAsyncContextInternal();
    }

    @Override
    public DispatcherType getDispatcherType() {

        return this.request.getDispatcherType();
    }

    @Override
    public void addCookie(Cookie cookie) {

        this.request.addCookie(cookie);
    }

    @Override
    public void addLocale(Locale locale) {

        this.request.addLocale(locale);
    }

    @Override
    public void clearCookies() {

        this.request.clearCookies();
    }

    @Override
    public void clearLocales() {

        this.request.clearLocales();
    }

    @Override
    public void setRequestedSessionCookie(boolean flag) {

        this.request.setRequestedSessionCookie(flag);
    }

    @Override
    public void setRequestedSessionURL(boolean flag) {

        this.request.setRequestedSessionURL(flag);
    }

    @Override
    public void setRequestedSessionSSL(boolean flag) {

        this.request.setRequestedSessionSSL(flag);
    }

    @Override
    public String getDecodedRequestURI() {

        return this.request.getDecodedRequestURI();
    }

    @Override
    public MessageBytes getDecodedRequestURIMB() {

        return this.request.getDecodedRequestURIMB();
    }

    @Override
    public boolean isTrailerFieldsReady() {

        return this.request.isTrailerFieldsReady();
    }

    @Override
    public Map<String, String> getTrailerFields() {

        return this.request.getTrailerFields();
    }

    @Override
    public PushBuilder newPushBuilder() {

        return this.request.newPushBuilder();
    }

    @Override
    public PushBuilder newPushBuilder(HttpServletRequest request) {

        return this.request.newPushBuilder(request);
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(Class<T> httpUpgradeHandlerClass)
            throws IOException, ServletException {

        return this.request.upgrade(httpUpgradeHandlerClass);
    }

    @Override
    public String getAuthType() {

        return this.request.getAuthType();
    }

    @Override
    public void setAuthType(String type) {

        this.request.setAuthType(type);
    }

    @Override
    public String getContextPath() {

        return this.request.getContextPath();
    }

    @Override
    public Cookie[] getCookies() {

        return this.request.getCookies();
    }

    @Override
    public ServerCookies getServerCookies() {

        return this.request.getServerCookies();
    }

    @Override
    public long getDateHeader(String name) {

        return this.request.getDateHeader(name);
    }

    @Override
    public String getHeader(String name) {

        return this.request.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {

        return this.request.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {

        return this.request.getHeaderNames();
    }

    @Override
    public int getIntHeader(String name) {

        return this.request.getIntHeader(name);
    }

    @Override
    public HttpServletMapping getHttpServletMapping() {

        return this.request.getHttpServletMapping();
    }

    @Override
    public String getMethod() {

        return this.request.getMethod();
    }

    @Override
    public String getPathInfo() {

        return this.request.getPathInfo();
    }

    @Override
    public void setPathInfo(String path) {

        this.request.setPathInfo(path);
    }

    @Override
    public String getPathTranslated() {

        return this.request.getPathTranslated();
    }

    @Override
    public String getQueryString() {

        return this.request.getQueryString();
    }

    @Override
    public String getRemoteUser() {

        return this.request.getRemoteUser();
    }

    @Override
    public MessageBytes getRequestPathMB() {

        return this.request.getRequestPathMB();
    }

    @Override
    public String getRequestedSessionId() {

        return this.request.getRequestedSessionId();
    }

    @Override
    public void setRequestedSessionId(String id) {

        this.request.setRequestedSessionId(id);
    }

    @Override
    public String getRequestURI() {

        return this.request.getRequestURI();
    }

    @Override
    public StringBuffer getRequestURL() {

        return this.request.getRequestURL();
    }

    @Override
    public String getServletPath() {

        return this.request.getServletPath();
    }

    @Override
    public HttpSession getSession() {

        return this.request.getSession();
    }

    @Override
    public HttpSession getSession(boolean create) {

        return this.request.getSession(create);
    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {

        return this.request.isRequestedSessionIdFromCookie();
    }

    @Override
    public boolean isRequestedSessionIdFromURL() {

        return this.request.isRequestedSessionIdFromURL();
    }

    @Override
    public boolean isRequestedSessionIdFromUrl() {

        return this.request.isRequestedSessionIdFromUrl();
    }

    @Override
    public boolean isRequestedSessionIdValid() {

        return this.request.isRequestedSessionIdValid();
    }

    @Override
    public boolean isUserInRole(String role) {

        return this.request.isUserInRole(role);
    }

    @Override
    public Principal getPrincipal() {

        return this.request.getPrincipal();
    }

    @Override
    public Principal getUserPrincipal() {

        return this.request.getUserPrincipal();
    }

    @Override
    public void setUserPrincipal(Principal principal) {

        this.request.setUserPrincipal(principal);
    }

    @Override
    public Session getSessionInternal() {

        return this.request.getSessionInternal();
    }

    @Override
    public void changeSessionId(String newSessionId) {

        this.request.changeSessionId(newSessionId);
    }

    @Override
    public String changeSessionId() {

        return this.request.changeSessionId();
    }

    @Override
    public Session getSessionInternal(boolean create) {

        return this.request.getSessionInternal(create);
    }

    @Override
    public boolean isParametersParsed() {

        return this.request.isParametersParsed();
    }

    @Override
    public boolean isFinished() {

        return this.request.isFinished();
    }

    @Override
    public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {

        return this.request.authenticate(response);
    }

    @Override
    public void login(String username, String password) throws ServletException {

        this.request.login(username, password);
    }

    @Override
    public void logout() throws ServletException {

        this.request.logout();
    }

    @Override
    public Collection<Part> getParts() throws IOException, IllegalStateException, ServletException {

        return this.request.getParts();
    }

    @Override
    public Part getPart(String name) throws IOException, IllegalStateException, ServletException {

        return this.request.getPart(name);
    }

    @Override
    public int hashCode() {

        return this.request.hashCode();
    }

    @Override
    public boolean equals(Object obj) {

        return this.request.equals(obj);
    }

    @Override
    public String toString() {

        return this.request.toString();
    }
}
