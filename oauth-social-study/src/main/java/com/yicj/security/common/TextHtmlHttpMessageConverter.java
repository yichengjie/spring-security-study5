package com.yicj.security.common;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.Charset;

public class TextHtmlHttpMessageConverter extends AbstractHttpMessageConverter<String> {
    public TextHtmlHttpMessageConverter(){
        super(Charset.forName("UTF-8"), new MediaType[]{MediaType.TEXT_HTML});
    }
    @Override
    protected boolean supports(Class clazz) {
        return String.class == clazz;
    }

    @Override
    protected String readInternal(Class clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
        Charset charset = this.getContentTypeCharset(inputMessage.getHeaders().getContentType()) ;
        return StreamUtils.copyToString(inputMessage.getBody(), charset);
    }
    @Override
    protected void writeInternal(String o, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
    }
    private Charset getContentTypeCharset(MediaType contentType){
        return contentType != null && contentType.getCharset() !=null
                ? contentType.getCharset() : this.getDefaultCharset() ;
    }
}
