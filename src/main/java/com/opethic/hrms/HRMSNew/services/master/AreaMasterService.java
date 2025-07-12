package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.AreaMaster;
import com.opethic.hrms.HRMSNew.models.master.Branch;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.AreaMasterRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class AreaMasterService {
    @Autowired
    private AreaMasterRepository areaMasterRepository;
    @Autowired
    JwtTokenUtil jwtRequestFilter;
    private static final Logger areaLogger = LogManager.getLogger(AreaMasterService.class);

    public Object createAreaMaster(HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        Branch branch = null;
        if (users.getBranch() != null) branch = users.getBranch();
        try {
            AreaMaster areaMaster = new AreaMaster();
            areaMaster.setAreaName(request.getParameter("areaName").trim());
            areaMaster.setBranch(branch);
            areaMaster.setCompany(users.getCompany());
            areaMaster.setCreatedBy(users.getId());
            areaMaster.setUpdatedBy(users.getId());
            areaMaster.setStatus(true);
            if (paramMap.containsKey("areaCode"))
                areaMaster.setAreaCode(request.getParameter("areaCode"));
            if (paramMap.containsKey("pincode"))
                areaMaster.setPincode(request.getParameter("pincode"));
            AreaMaster mArea = areaMasterRepository.save(areaMaster);
            responseObject.setMessage("Area Master created succussfully");
            responseObject.setResponseStatus(HttpStatus.OK.value());
            responseObject.setResponse(mArea.getId().toString());
        } catch (DataIntegrityViolationException e) {
            e.printStackTrace();
            areaLogger.error("createAreaMaster-> failed to create AreaMaster" + e);
            responseObject.setMessage("Internal Server Error");
            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        } catch (Exception e1) {
            e1.printStackTrace();
            areaLogger.error("createAreaMaster-> failed to create AreaMaster" + e1);
            responseObject.setMessage("Error");
        }
        return responseObject;
    }

    public JsonObject getAllAreaMaster(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        JsonObject res = new JsonObject();
        Long outletId = users.getCompany().getId();
        List<AreaMaster> list = new ArrayList<>();
        if (users.getBranch() != null) {
            list = areaMasterRepository.findByCompanyIdAndStatusAndBranchId(outletId, true, users.getBranch().getId());
        } else {
            list = areaMasterRepository.findByCompanyIdAndStatusAndBranchIsNull(outletId, true);
        }
        if (list.size() > 0) {
            for (AreaMaster mArea : list) {
                JsonObject response = new JsonObject();
                response.addProperty("id", mArea.getId());
                response.addProperty("areaName", mArea.getAreaName());
                response.addProperty("areaCode", mArea.getAreaCode() != null ? mArea.getAreaCode() : "");
                response.addProperty("pincode", mArea.getPincode() != null ? mArea.getPincode() : "");
                result.add(response);
            }
            res.addProperty("message", "success");
            res.addProperty("responseStatus", HttpStatus.OK.value());
            res.add("responseObject", result);

        } else {
            res.addProperty("message", "empty list");
            res.addProperty("responseStatus", HttpStatus.OK.value());
            res.add("responseObject", result);
        }
        return res;
    }

    public JsonObject getAreaMaster(HttpServletRequest request) {
        AreaMaster area = areaMasterRepository.findByIdAndStatus(Long.parseLong(request.getParameter("id")), true);
        JsonObject response = new JsonObject();
        JsonObject result = new JsonObject();
        if (area != null) {
            response.addProperty("id", area.getId());
            response.addProperty("areaName", area.getAreaName());
            response.addProperty("areaCode", area.getAreaCode() != null ? area.getAreaCode() : "");
            response.addProperty("pincode", area.getPincode() != null ? area.getPincode() : "");
            result.addProperty("message", "success");
            result.addProperty("responseStatus", HttpStatus.OK.value());
            result.add("responseObject", response);
        } else {
            result.addProperty("message", "not found");
            result.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
        }
        return result;
    }

    public JsonObject updateAreaMaster(HttpServletRequest request) {
        JsonObject responseObject = new JsonObject();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Branch branch = null;
        Map<String, String[]> paramMap = request.getParameterMap();
        if (users.getBranch() != null) branch = users.getBranch();
        try {
            AreaMaster areaMaster = areaMasterRepository.findByIdAndStatus(Long.parseLong(request.getParameter("id")), true);
            areaMaster.setAreaName(request.getParameter("areaName").trim());
            areaMaster.setBranch(branch);
            areaMaster.setCompany(users.getCompany());
            areaMaster.setCreatedBy(users.getId());
            areaMaster.setUpdatedBy(users.getId());
            if (paramMap.containsKey("areaCode"))
                areaMaster.setAreaCode(request.getParameter("areaCode"));
            if (paramMap.containsKey("pincode"))
                areaMaster.setPincode(request.getParameter("pincode"));
            AreaMaster mArea = areaMasterRepository.save(areaMaster);
            responseObject.addProperty("message", "Area Master updated succussfully");
            responseObject.addProperty("responseStatus", HttpStatus.OK.value());
            responseObject.addProperty("responseObject", mArea.getId().toString());
        } catch (DataIntegrityViolationException e) {
            e.printStackTrace();
            areaLogger.error("updateAreaMaster-> failed to update AreaMaster" + e);
            responseObject.addProperty("message", "Internal Server Error");
            responseObject.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        } catch (Exception e1) {
            e1.printStackTrace();
            areaLogger.error("updateAreaMaster-> failed to update AreaMaster" + e1);
            responseObject.addProperty("message", "Error");
        }
        return responseObject;
    }

    public JsonObject removeAreaMaster(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject jsonObject = new JsonObject();
        AreaMaster areaMaster = areaMasterRepository.findByIdAndStatus(Long.parseLong(request.getParameter("id")), true);
        if (areaMaster != null) {
            areaMaster.setStatus(false);
            areaMasterRepository.save(areaMaster);
            jsonObject.addProperty("message", "Area Master deleted successfully");
            jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
        } else {
            jsonObject.addProperty("message", "Error in Area Master deletion");
            jsonObject.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return jsonObject;
    }
}
