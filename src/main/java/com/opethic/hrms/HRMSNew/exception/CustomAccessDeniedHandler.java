package com.opethic.hrms.HRMSNew.exception;

import com.google.gson.JsonObject;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.AccessDeniedException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, org.springframework.security.access.AccessDeniedException accessDeniedException) throws IOException, ServletException {
        Authentication auth
                = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            System.out.println("User: " + auth.getName()
                    + " attempted to access the protected URL: "
                    + request.getRequestURI());
        }
        System.out.println("  attempted to access the protected URL ");

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("message", "Access denied to access protected data!!");
        jsonObject.addProperty("responseStatus", HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        // for setting 401 status code as serverside, if we commented below line then its consider api response as 200
//        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().println(jsonObject.toString());
    }
}