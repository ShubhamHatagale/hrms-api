package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.BreakMaster;
import com.opethic.hrms.HRMSNew.models.master.Employee;
import com.opethic.hrms.HRMSNew.models.master.LeaveMaster;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.LeaveMasterRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class LeaveMasterService {
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private LeaveMasterRepository leaveMasterRepository;

    public Object createLeaveMaster(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        LeaveMaster leaveMaster = new LeaveMaster();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            leaveMaster.setName(requestParam.get("name"));
            leaveMaster.setIsPaid(Boolean.valueOf(requestParam.get("isPaid")));
            leaveMaster.setLeavesAllowed(Long.valueOf(requestParam.get("leavesAllowed")));
            leaveMaster.setCreatedBy(users.getId());
            leaveMaster.setCompany(users.getCompany());
            leaveMaster.setBranch(users.getBranch());
            leaveMaster.setStatus(true);
            try {
                leaveMasterRepository.save(leaveMaster);
                responseMessage.setMessage("Leave Master created successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to create leave master");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to create leave master");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public Object findLeaveMaster(Map<String, String> requestParam) {
        ResponseMessage responseMessage = new ResponseMessage();
        LeaveMaster leaveMaster = leaveMasterRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
        if (leaveMaster != null) {
            responseMessage.setResponse(leaveMaster);
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        } else {
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }
    public Object updateLeaveMaster(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Long id = Long.valueOf(requestParam.get("id"));
        LeaveMaster leaveMaster = leaveMasterRepository.findByIdAndStatus(id, true);
        if (leaveMaster != null) {
            try {
                Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
                leaveMaster.setName(requestParam.get("name"));
                leaveMaster.setIsPaid(Boolean.valueOf(requestParam.get("isPaid")));
                leaveMaster.setLeavesAllowed(Long.valueOf(requestParam.get("leavesAllowed")));
                leaveMaster.setUpdatedBy(users.getId());
                leaveMaster.setUpdatedAt(LocalDateTime.now());
                leaveMaster.setStatus(true);
                try {
                    leaveMasterRepository.save(leaveMaster);
                    responseMessage.setMessage("Leave Master updated successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception " + e.getMessage());
                    responseMessage.setMessage("Failed to update leave master");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to update leave master");
                responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            }
        } else {
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }
    public Object deleteLeaveMaster(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        LeaveMaster leaveMaster = leaveMasterRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")), true);
        if (leaveMaster != null) {
            leaveMaster.setStatus(false);
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            leaveMaster.setUpdatedBy(user.getId());
            leaveMaster.setUpdatedAt(LocalDateTime.now());
            try {
                leaveMasterRepository.save(leaveMaster);
                responseObject.setMessage("Leave Master deleted successfully");
                responseObject.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                responseObject.setMessage("Failed to delete leave master");
                e.printStackTrace();
                System.out.println("Exception:" + e.getMessage());
            }
        } else {
            responseObject.setMessage("Data not found");
            responseObject.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseObject;
    }
    public JsonObject listForSelection(HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            List<LeaveMaster> leaveMasterList = leaveMasterRepository.findByCompanyIdAndStatus(employee.getCompany().getId(), true);
            for (LeaveMaster leaveMaster : leaveMasterList) {
                JsonObject object = new JsonObject();
                object.addProperty("id", leaveMaster.getId());
                object.addProperty("name", leaveMaster.getName());
                object.addProperty("isPaid", leaveMaster.getIsPaid());
                jsonArray.add(object);
            }
            responseMessage.add("response", jsonArray);
            responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }
    public JsonObject leavesDashboard(HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        Employee employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            List<Object[]> leaveCountList = leaveMasterRepository.getEmployeeLeavesDashboardData(employee.getId(), employee.getCompany().getId(), employee.getBranch().getId());
            if(leaveCountList.size() > 0) {
                for (int i = 0; i < leaveCountList.size(); i++) {
                    Object[] obj = leaveCountList.get(i);
                    JsonObject leaveObject = new JsonObject();
                    leaveObject.addProperty("name", obj[0].toString());
                    leaveObject.addProperty("id", obj[1].toString());
                    leaveObject.addProperty("leaves_allowed", obj[2].toString());
                    leaveObject.addProperty("usedleaves", obj[3].toString());
                    Long leaveAllowed = Long.parseLong(obj[2].toString());
                    Long used = Long.parseLong(obj[3].toString());
                    Long remaining = leaveAllowed - used;
                    leaveObject.addProperty("remainingleaves", remaining);
                    jsonArray.add(leaveObject);
                }
                responseMessage.add("response", jsonArray);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("message", "No Data Found");
                responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }
    public JsonObject listOfLeaveMasters(HttpServletRequest request) {
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<LeaveMaster> leaveMasterList = null;
        try {
            leaveMasterList = leaveMasterRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(),true);
            if(leaveMasterList != null) {
                for (LeaveMaster leaveMaster : leaveMasterList) {
                    JsonObject object = new JsonObject();
                    object.addProperty("id", leaveMaster.getId());
                    object.addProperty("leaveName", leaveMaster.getName());
                    object.addProperty("isPaid", leaveMaster.getIsPaid());
                    object.addProperty("leavesAllowed", leaveMaster.getLeavesAllowed());
                    jsonArray.add(object);
                }
                responseMessage.add("response", jsonArray);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("message", "Data not found");
                responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

}
