package com.opethic.hrms.HRMSNew.services.master;


import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.Country;
import com.opethic.hrms.HRMSNew.repositories.master.CountryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Service
public class CountryService {
    @Autowired
    private CountryRepository repository;

    public JsonObject getCountry(HttpServletRequest request) {
        List<Country> list  = repository.findAll();
        JsonObject jsonObject = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        for(Country mcountry:list){
            JsonObject res = new JsonObject();
            res.addProperty("id",mcountry.getId());
            res.addProperty("countryName",mcountry.getName());
            jsonArray.add(res);
        }
        jsonObject.addProperty("message","success");
        jsonObject.addProperty("responseStatu", HttpStatus.OK.value());
        jsonObject.add("responseObject",jsonArray);
        return jsonObject;
    }

    public Object getIndiaCountry(HttpServletRequest request) {
        Country country = repository.findByName("India");
        return country;

    }
}
