package com.opethic.hrms.HRMSNew.services.master;


import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.State;
import com.opethic.hrms.HRMSNew.repositories.master.CountryRepository;
import com.opethic.hrms.HRMSNew.repositories.master.StateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Service
public class StateService {
    @Autowired
    private StateRepository repository;
    @Autowired
    private CountryRepository countryRepository;

    public JsonObject getState(HttpServletRequest request) {
        List<State> list = repository.findAll();
        JsonObject res = getStateData(list);
        return res;
    }

    public JsonObject getIndianState(HttpServletRequest request) {

        List<State> states = repository.findByCountryCode("IN");
        JsonObject res = getStateData(states);
        return res;
    }

    public JsonObject getStateData(List<State> list) {
        JsonArray result = new JsonArray();
        JsonObject res = new JsonObject();
        if (list.size() > 0) {
            for (State mState : list) {
                JsonObject response = new JsonObject();
                response.addProperty("id", mState.getId());
                response.addProperty("stateName", mState.getName());
                response.addProperty("stateCode", mState.getStateCode());
                result.add(response);
            }
            res.addProperty("message", "success");
            res.addProperty("responseStatus", HttpStatus.OK.value());
            res.add("responseObject", result);
        } else {
            res.addProperty("message", "empty list");
            res.addProperty("responseStatus", HttpStatus.OK.value());
        }
        return res;
    }
}
