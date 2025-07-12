package com.opethic.hrms.HRMSNew.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
public class SwaggerConfig {

    public static final String AUTHORIZATION_HEADER="Authorization";

    private ApiKey apiKeys(){
        return new ApiKey("JWT",AUTHORIZATION_HEADER, "header");
    }

    private List<SecurityContext> securityContextList(){
        return Arrays.asList(SecurityContext.builder().securityReferences(securityReferenceList()).build());
    }
    private List<SecurityReference> securityReferenceList(){
        AuthorizationScope authorizationScope = new AuthorizationScope("global","accessEverything");
        return Arrays.asList(new SecurityReference("JWT", new AuthorizationScope[]{authorizationScope}));
    }
    @Bean
    public Docket api(){
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(getInfo())
                .securityContexts(securityContextList())
                .securitySchemes(Arrays.asList(apiKeys()))
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.any())
                .build();
    }

    private ApiInfo getInfo() {
        return new ApiInfo(
                "Blogging Application : Backend",
                "This project is developed by HRMS Team",
                "1.0",
                "Terms of Services",
                new Contact("Opethic LLP", "opethic.google.com", "opethic@gmail.com"),
                "license key",
                "license.google.com",
                Collections.emptyList());
    }
}
