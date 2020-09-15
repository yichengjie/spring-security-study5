package com.yicj.security.common;

import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;

import java.util.ArrayList;
import java.util.List;

// 添加RestTemplate解析模板
public class JacksonFromTextHtmlHttpMessageConverter extends MappingJackson2HttpMessageConverter {
    // 添加对text/html的支持
    public JacksonFromTextHtmlHttpMessageConverter(MediaType mediaType){
        List<MediaType> mediaTypes = new ArrayList() ;
        mediaTypes.add(mediaType) ;
        setSupportedMediaTypes(mediaTypes);
    }
}
