package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.dto.BreakDTDTO;
import com.opethic.hrms.HRMSNew.dto.ShiftDTDTO;
import com.opethic.hrms.HRMSNew.models.master.BreakMaster;
import com.opethic.hrms.HRMSNew.models.master.Employee;
import com.opethic.hrms.HRMSNew.models.master.Shift;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.master.BreakMasterRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;

@Service
public class BreakMasterService {

    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private BreakMasterRepository workBreakMasterRepository;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    public Object createBreak(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        BreakMaster workBreakMaster = new BreakMaster();
        workBreakMaster.setBreakName(requestParam.get("breakName"));
        LocalTime fromTime = LocalTime.parse(requestParam.get("fromTime"));
        workBreakMaster.setFromTime(fromTime);
        LocalTime toTime = LocalTime.parse(requestParam.get("toTime"));
        workBreakMaster.setToTime(toTime);
//        workBreak.setIsBreakPaid(Boolean.parseBoolean(requestParam.get("isBreakPaid")));
        workBreakMaster.setStatus(true);

        workBreakMaster.setCreatedBy(users.getId());
        workBreakMaster.setCreatedAt(LocalDateTime.now());
        workBreakMaster.setCompany(users.getCompany());
        workBreakMaster.setBranch(users.getBranch());
        try {
            workBreakMasterRepository.save(workBreakMaster);
            responseMessage.setMessage("Break created successfully");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception e");
            responseMessage.setMessage("Failed to create work break");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object findBreak(Map<String, String> request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Long id = Long.parseLong(request.get("id"));
        try {
            BreakMaster workBreakMaster = workBreakMasterRepository.findByIdAndStatus(id, true);
            if (workBreakMaster != null) {
                BreakDTDTO breakDTDTO=convertToDTO(workBreakMaster);
                responseMessage.setResponse(breakDTDTO);
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } else {
                responseMessage.setMessage("Data not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            responseMessage.setMessage("Failed to load data");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }


    private BreakDTDTO convertToDTO(BreakMaster workBreakMaster) {
        BreakDTDTO breakDTDTO = new BreakDTDTO();
        breakDTDTO.setId(workBreakMaster.getId());
        breakDTDTO.setBreakName(workBreakMaster.getBreakName());
        breakDTDTO.setFromTime(String.valueOf(workBreakMaster.getFromTime()));
        breakDTDTO.setToTime(String.valueOf(workBreakMaster.getToTime()));
        breakDTDTO.setCreatedBy(workBreakMaster.getCreatedBy());
        breakDTDTO.setCreatedAt(LocalDateTime.parse(String.valueOf(workBreakMaster.getCreatedAt())));
        breakDTDTO.setUpdatedBy(workBreakMaster.getUpdatedBy());
        if (workBreakMaster.getUpdatedAt() != null)
            breakDTDTO.setUpdatedAt(LocalDateTime.parse(String.valueOf(workBreakMaster.getUpdatedAt())));
        return breakDTDTO;
    }

    public Object updateBreak(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Long id = Long.parseLong(requestParam.get("id"));
        try {
            BreakMaster workBreakMaster = workBreakMasterRepository.findByIdAndStatus(id, true);
            if (workBreakMaster != null) {
                Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
                workBreakMaster.setBreakName(requestParam.get("breakName"));
                LocalTime fromTime = LocalTime.parse(requestParam.get("fromTime"));
                workBreakMaster.setFromTime(fromTime);
                LocalTime toTime = LocalTime.parse(requestParam.get("toTime"));
                workBreakMaster.setToTime(toTime);
//                workBreak.setIsBreakPaid(Boolean.parseBoolean(requestParam.get("isBreakPaid")));
                workBreakMaster.setStatus(true);
                workBreakMaster.setUpdatedBy(users.getId());
                workBreakMaster.setUpdatedAt(LocalDateTime.now());
                workBreakMaster.setCompany(users.getCompany());
                workBreakMaster.setBranch(users.getBranch());
                try {
                    workBreakMasterRepository.save(workBreakMaster);
                    responseMessage.setMessage("Break updated successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception e");
                    responseMessage.setMessage("Failed to create Break");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } else {
                responseMessage.setMessage("Data not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            responseMessage.setMessage("Failed to load data");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject listOfBreak(Map<String, String> request, HttpServletRequest httpServletRequest) {
        JsonObject responseMessage = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        Employee employee = null;
        List<BreakMaster> workBreakListMaster = null;
        try {
            if(request.containsKey("isOwner")){
                if(Boolean.parseBoolean(request.get("isOwner"))){
                    Users users = jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
                    if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("SADMIN")){
                        workBreakListMaster = workBreakMasterRepository.findAllByStatus(true);
                    } else if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("CADMIN")) {
                        workBreakListMaster = workBreakMasterRepository.findAllByCompanyIdAndStatus(users.getCompany().getId(),true);
                    } else if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
                        workBreakListMaster = workBreakMasterRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), true);
                    }
                } else {
                    employee = jwtTokenUtil.getEmployeeDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
                    workBreakListMaster = workBreakMasterRepository.findAllByCompanyIdAndStatus(employee.getCompany().getId(), true);
                }
            } else {
                employee = jwtTokenUtil.getEmployeeDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
                workBreakListMaster = workBreakMasterRepository.findAllByCompanyIdAndBranchIdAndStatus(employee.getCompany().getId(),employee.getBranch().getId(), true);
            }
            if(workBreakListMaster != null) {
                for (BreakMaster workBreakMaster : workBreakListMaster) {
                    JsonObject object = new JsonObject();
                    object.addProperty("id", workBreakMaster.getId());
                    object.addProperty("breakName", workBreakMaster.getBreakName());
//                object.addProperty("isPaid", workBreak.getIsBreakPaid());
                    object.addProperty("fromTime", workBreakMaster.getFromTime().toString());
                    object.addProperty("toTime", workBreakMaster.getToTime().toString());
                    object.addProperty("createdDate", workBreakMaster.getCreatedAt().toString());

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

    public Object deleteBreak(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Long id = Long.parseLong(requestParam.get("id"));
        try {
            BreakMaster workBreakMaster = workBreakMasterRepository.findByIdAndStatus(id, true);
            if (workBreakMaster != null) {
                Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
                workBreakMaster.setStatus(false);
                workBreakMaster.setUpdatedBy(users.getId());
                workBreakMaster.setUpdatedAt(LocalDateTime.now());
                workBreakMaster.setCompany(users.getCompany());
                workBreakMaster.setBranch(users.getBranch());
                try {
                    workBreakMasterRepository.save(workBreakMaster);
                    responseMessage.setMessage("Break deleted successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception e");
                    responseMessage.setMessage("Failed to create Break");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } else {
                responseMessage.setMessage("Data not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            responseMessage.setMessage("Failed to load data");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

}
