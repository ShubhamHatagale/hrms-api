package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.BalancingMethod;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.BalancingMethodRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Service
public class BalancingMethodService {

    @Autowired
    BalancingMethodRepository repository;
    @Autowired
    JwtTokenUtil jwtRequestFilter;

    private static final Logger balancingMethodLogger = LoggerFactory.getLogger(BalancingMethodService.class);

    public Object createBalancingMethod(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        BalancingMethod balancingMethod = new BalancingMethod();
        balancingMethod.setBalancingMethod(request.getParameter("balancing_method"));
        balancingMethod.setStatus(true);
        balancingMethod.setCreatedBy(users.getId());
        ResponseMessage responseMessage = new ResponseMessage();


        try {
            repository.save(balancingMethod);
            responseMessage.setMessage("Balancing method created successfully");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            balancingMethodLogger.error("createBalancingMethod -> failed to create Balancing method" + e);

        System.out.println(e.getMessage());
        }
        return responseMessage;
    }

    public JsonObject getBalancingMethod(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        JsonObject output = new JsonObject();
        List<BalancingMethod> list = new ArrayList<>();
        list = repository.findAll();
        if (list.size() > 0) {
            for (BalancingMethod mBal : list) {
                JsonObject response = new JsonObject();
                response.addProperty("balancing_id", mBal.getId());
                response.addProperty("balance_method", mBal.getBalancingMethod());
                result.add(response);
            }
            output.addProperty("message", "success");
            output.addProperty("responseStatus", HttpStatus.OK.value());
            output.add("response", result);
        } else {
            output.addProperty("message", "empty list");
            output.addProperty("responseStatus", HttpStatus.OK.value());
            output.add("response", result);
        }
        return output;
    }

}
