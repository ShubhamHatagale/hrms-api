package com.opethic.hrms.HRMSNew.services.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.config.AppConfig;
import com.opethic.hrms.HRMSNew.config.SystemConfigParameter;
import com.opethic.hrms.HRMSNew.models.master.Branch;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.config.AppConfigRepository;
import com.opethic.hrms.HRMSNew.repositories.config.SystemConfigParameterRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Service
public class AppConfigService {
    @Autowired
    private JwtTokenUtil jwtRequestFilter;
    @Autowired
    private AppConfigRepository repository;
    @Autowired
    private SystemConfigParameterRepository systemConfigParameterRepository;
    private static final Logger appconfigLogger = LogManager.getLogger(AppConfigService.class);

    public Object addConfig(HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Branch branch = null;
        String strJson = request.getParameter("settings");
        JsonArray settingArray = new JsonParser().parse(strJson).getAsJsonArray();
        try {
            if (users.getBranch() != null) {
                branch = users.getBranch();
            }
            for (JsonElement jsonElement : settingArray) {
                JsonObject object = jsonElement.getAsJsonObject();
                AppConfig appConfig = new AppConfig();
                appConfig.setConfigName(object.get("key").getAsString());
                if (object.get("value").getAsBoolean())
                    appConfig.setConfigValue(1);
                else
                    appConfig.setConfigValue(0);
                appConfig.setConfigLabel(object.get("label").getAsString());
                appConfig.setBranch(branch);
                appConfig.setCompany(users.getCompany());
                appConfig.setCreatedBy(users.getId());
                appConfig.setUpdatedBy(users.getId());
                appConfig.setStatus(true);
                AppConfig mAppConfig = repository.save(appConfig);
                responseObject.setMessage("Created Successfully");
                responseObject.setResponseStatus(HttpStatus.OK.value());
                responseObject.setResponse(mAppConfig.getId().toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
            appconfigLogger.error("addConfig()-> failed to crate Configuration" + e);
            responseObject.setMessage("Internal server Error");
            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseObject;
    }

    public JsonObject updateConfig(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        try {
            String strJson = request.getParameter("userControlData");
            JsonArray settingArray = new JsonParser().parse(strJson).getAsJsonArray();
            for (JsonElement jsonElement : settingArray) {
                JsonObject object = jsonElement.getAsJsonObject();
                AppConfig appConfig = repository.findByIdAndStatus(object.get("id").getAsLong(), true);
                appConfig.setConfigName(object.get("slug").getAsString());
                if (object.get("value").getAsBoolean())
                    appConfig.setConfigValue(object.get("value").getAsInt());
                else
                    appConfig.setConfigValue(object.get("value").getAsInt());
                appConfig.setConfigLabel(object.get("label").getAsString());
                appConfig.setUpdatedBy(users.getId());
                AppConfig mAppConfig = repository.save(appConfig);
                response.addProperty("message", "Configuration Updated successfully");
                response.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            appconfigLogger.error("updateLevelC-> failed to updateLevelC" + e);
        }
        return response;
    }

    public JsonObject getAllCompanyAppConfig(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        JsonObject res = new JsonObject();
        JsonObject finalres = new JsonObject();
        Long companyId = users.getCompany().getId();
        List<AppConfig> list = new ArrayList<>();
        if (users.getBranch() != null) {
            list = repository.findByCompanyIdAndStatusAndBranchId(companyId, true, users.getBranch().getId());
        } else {
            list = repository.findByCompanyIdAndStatusAndBranchIsNull(companyId, true);
        }
        if (list.size() > 0) {
            for (AppConfig mConfig : list) {
                JsonObject response = new JsonObject();
                response.addProperty("id", mConfig.getId());
                response.addProperty("slug", mConfig.getConfigName());
                response.addProperty("display_name", mConfig.getSystemConfigParameter().getDisplayName());
                response.addProperty("value", mConfig.getConfigValue());
                response.addProperty("is_label", mConfig.getSystemConfigParameter().getIsLabel());
                response.addProperty("label", mConfig.getConfigLabel());
                result.add(response);
            }
            // finalres.add("settings", result);
            res.addProperty("message", "success");
            res.addProperty("responseStatus", HttpStatus.OK.value());
            res.add("responseObject", result);
        } else {
            res.add("responseObject", result);
            res.addProperty("message", "empty list");
            res.addProperty("responseStatus", HttpStatus.OK.value());
        }
        return res;
    }

    public JsonObject getappConfigById(HttpServletRequest request) {
        AppConfig config = repository.findByIdAndStatus(Long.parseLong(
                request.getParameter("id")), true);
        JsonObject response = new JsonObject();
        JsonObject result = new JsonObject();
        if (config != null) {
            response.addProperty("id", config.getId());
            response.addProperty("configName", config.getConfigName());
            response.addProperty("configValue", config.getConfigValue());
            result.addProperty("message", "success");
            result.addProperty("responseStatus", HttpStatus.OK.value());
            result.add("responseObject", response);
        } else {
            result.addProperty("message", "LevelC Not found");
            result.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
        }
        return result;
    }

    public JsonObject removeAppConfig(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject jsonObject = new JsonObject();
        Long appId = Long.parseLong(request.getParameter("id"));
        AppConfig appConfig = null;
        appConfig = repository.findByIdAndStatus(appId, true);
        if (appConfig != null)
            appConfig.setStatus(false);
        try {
            repository.save(appConfig);
            jsonObject.addProperty("message", "Configuration Deleted Successfully");
            jsonObject.addProperty("responseStatus", HttpStatus.OK.value());

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
            e.getMessage();
            e.printStackTrace();
        }
        return jsonObject;
    }

    public JsonObject getMasterSystemAppConfig(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        JsonObject res = new JsonObject();
        List<SystemConfigParameter> list = new ArrayList<>();
        list = systemConfigParameterRepository.findByStatus(true);
        if (list.size() > 0) {
            for (SystemConfigParameter mConfig : list) {
                JsonObject response = new JsonObject();
                response.addProperty("id", mConfig.getId());
                response.addProperty("display_name", mConfig.getDisplayName());
                response.addProperty("slug", mConfig.getSlug());
                response.addProperty("value",false);
                response.addProperty("is_label", mConfig.getIsLabel());

                result.add(response);
            }
            res.addProperty("message", "success");
            res.addProperty("responseStatus", HttpStatus.OK.value());
            res.add("responseObject", result);
        } else {
            res.add("responseObject", result);
            res.addProperty("message", "empty list");
            res.addProperty("responseStatus", HttpStatus.OK.value());
        }
        return res;
    }
}
