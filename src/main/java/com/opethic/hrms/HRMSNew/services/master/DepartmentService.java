package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.models.master.Department;
import com.opethic.hrms.HRMSNew.repositories.master.DepartmentRepository;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class DepartmentService {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private DepartmentRepository departmentRepository;

    public Object createDepartment(Map<String,String> requestParam, HttpServletRequest request){
        ResponseMessage responseObject=new ResponseMessage();
        Department department=new Department();
        department.setDepartmentName(requestParam.get("departmentName"));
        department.setStatus(true);
        if(request.getHeader("Authorization")!=null){
            Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            department.setCreatedBy(users.getId());
            department.setCompany(users.getCompany());
            department.setBranch(users.getBranch());
        }
        try{
            Department department1=departmentRepository.save(department);
            responseObject.setResponse(department1);
            responseObject.setMessage("Department Added Successfully");
            responseObject.setResponseStatus(HttpStatus.OK.value());
        }catch (Exception e){
            responseObject.setMessage("Failed to Create Department");
            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            e.printStackTrace();
            System.out.println("Exception"+e.getMessage());
        }
        return responseObject;
    }

    public JsonObject listOfDepartment(HttpServletRequest httpServletRequest){
        Users users=jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        JsonObject response=new JsonObject();
        JsonArray jsonArray=new JsonArray();
        try {
            if(users.getIsAdmin()){
                List<Department> departmentList=departmentRepository.findAllByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(),users.getBranch().getId(),true);
                for(Department department:departmentList){
                    JsonObject object=new JsonObject();
                    object.addProperty("id",department.getId());
                    object.addProperty("departmentName",department.getDepartmentName());
                    object.addProperty("createdDate",department.getCreatedAt().toString());
                    jsonArray.add(object);
                }
                response.add("response",jsonArray);
                response.addProperty("responseStatus",HttpStatus.OK.value());
            }
        }catch (Exception e){
            response.addProperty("message","Failed to Load Data");
            response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object findDepartment(Map<String,String> requestParam,HttpServletRequest request){
        ResponseMessage responseMessage=new ResponseMessage();
        Long departmentId=Long.parseLong(requestParam.get("id"));
        try {
            Department department=departmentRepository.findByIdAndStatus(departmentId,true);
            if(department!=null){
                responseMessage.setResponse(department);
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            }else {
                responseMessage.setMessage("Data not Found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        }catch (Exception e){
            System.out.println("Exception"+e.getMessage());
            responseMessage.setMessage("Data not Found");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object updateDepartment(Map<String,String> requestParam,HttpServletRequest request){
        ResponseMessage responseMessage=new ResponseMessage();
        Department department=departmentRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),true);
        Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        department.setDepartmentName(requestParam.get("departmentName"));
        department.setUpdatedBy(users.getId());
        department.setCompany(users.getCompany());
        department.setBranch(users.getBranch());
        try {
            departmentRepository.save(department);
            responseMessage.setMessage("Department Updated Successfully");;
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        }catch (Exception e){
            e.printStackTrace();
            System.out.println("Exception"+e.getMessage());
            responseMessage.setMessage("Failed to Update Department");
            responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseMessage;
    }

    public Object deleteDepartment(Map<String,String> requestParam,HttpServletRequest request){
        ResponseMessage responseMessage=new ResponseMessage();
        Users users=jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try{
            if (users!=null){
                Department department=departmentRepository.findByIdAndStatus(Long.parseLong(requestParam.get("id")),true);
                if(department!=null){
                    department.setStatus(false);
                    department.setUpdatedAt(LocalDateTime.now());
                    try {
                        departmentRepository.save(department);
                        responseMessage.setMessage("Department Deleted Successfully");
                        responseMessage.setResponseStatus(HttpStatus.OK.value());
                    }catch (Exception e){
                        System.out.println("Exception"+e.getMessage());
                        responseMessage.setMessage("Failed to Delete Department");
                        responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                }
            }else {
                responseMessage.setMessage("Invalid User");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        }catch (Exception e)
        {
            responseMessage.setMessage("Failed to Delete Department");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }
}
