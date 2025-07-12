package com.opethic.hrms.HRMSNew.services.master;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.dto.GenericDTData;
import com.opethic.hrms.HRMSNew.dto.PayheadDTO;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.master.BalancingMethodRepository;
import com.opethic.hrms.HRMSNew.repositories.master.PayheadRepository;
import com.opethic.hrms.HRMSNew.repositories.master.PrincipleGroupsRepository;
import com.opethic.hrms.HRMSNew.repositories.master.PrincipleRepository;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.persistence.*;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class PayheadService {
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private PayheadRepository payheadRepository;
    @Autowired
    Utility utility;
    @Autowired
    private PrincipleRepository principleRepository;
    @Autowired
    private BalancingMethodRepository balancingMethodRepository;
    @Autowired
    private LedgerMasterRepository ledgerMasterRepository;
    @Autowired
    private PrincipleGroupsRepository principleGroupsRepository;

    public Object createPayhead(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Payhead payhead = new Payhead();
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            payhead.setName(requestParam.get("payheadName"));
            payhead.setPercentage(Double.parseDouble(requestParam.get("percentage")));

            if (requestParam.get("payheadId") != null) {
                Long payheadId = Long.valueOf(requestParam.get("payheadId"));
                Payhead payhead1 = payheadRepository.findByIdAndStatus(payheadId, true);
                payhead.setPercentageOf(payhead1);
            }
            payhead.setPayheadSlug(utility.getKeyName(requestParam.get("payheadName"),false));
            payhead.setCreatedBy(users.getId());
            payhead.setCreatedAt(LocalDateTime.now());
            payhead.setCompany(users.getCompany());
            payhead.setBranch(users.getBranch());
            payhead.setStatus(true);
            if(Boolean.parseBoolean(requestParam.get("isDefault")))
                payhead.setIsDefault(true);
            else
                payhead.setIsDefault(false);
            payhead.setIsDeduction(Boolean.parseBoolean(requestParam.get("is_dedcution")));
            payhead.setShowInEmpCreation(Boolean.parseBoolean(requestParam.get("show_in_emp_creation")));
            try {
                Payhead object = payheadRepository.save(payhead);
                PrincipleGroups groups = null;
                Principles principles = null;
                Foundations foundations = null;
                BalancingMethod balancingMethod = null;
                if(object != null){
                    if(requestParam.containsKey("principle_group_id"))
                        groups = principleGroupsRepository.findByIdAndStatus(Long.parseLong(requestParam.get("principle_group_id")), true);
                    if(requestParam.containsKey("principle_id")) {
                        principles = principleRepository.findByIdAndStatus(Long.parseLong(requestParam.get("principle_id")), true);
                        foundations = principles.getFoundations();
                    }
                    LedgerMaster mLedgerMaster = new LedgerMaster();
                    mLedgerMaster.setPrincipleGroups(groups);
                    if(groups != null)
                        mLedgerMaster.setUniqueCode(groups.getUniqueCode());
                    else
                        mLedgerMaster.setUniqueCode(principles.getUniqueCode());
                    if (requestParam.containsKey("balancing_method")) {
                        balancingMethod = balancingMethodRepository.findByIdAndStatus(Long.parseLong(request.getParameter("balancing_method")), true);
                        mLedgerMaster.setBalancingMethod(balancingMethod);
                    }
                    if (requestParam.containsKey("opening_bal_type"))
                        mLedgerMaster.setOpeningBalType(requestParam.get("opening_bal_type"));
                    else
                        mLedgerMaster.setOpeningBalType(requestParam.get(""));
                    mLedgerMaster.setAddress("NA");
                    mLedgerMaster.setOpeningBal(0.0);
                    mLedgerMaster.setPincode(0L);
                    mLedgerMaster.setEmail("NA");
                    mLedgerMaster.setTaxable(false);
                    mLedgerMaster.setGstin("NA");
                    mLedgerMaster.setStateCode("NA");
                    mLedgerMaster.setPancard("NA");
                    mLedgerMaster.setBankName("NA");
                    mLedgerMaster.setAccountNumber("NA");
                    mLedgerMaster.setIfsc("NA");
                    mLedgerMaster.setBankBranch("NA");
                    mLedgerMaster.setCreatedBy(users.getId());
                    mLedgerMaster.setTaxType("NA");
                    if(groups != null)
                        mLedgerMaster.setSlugName(groups.getLedgerFormParameter().getSlugName());
                    else
                        mLedgerMaster.setSlugName(principles.getLedgerFormParameter().getSlugName());
                    mLedgerMaster.setStatus(true);
                    mLedgerMaster.setUnderPrefix(requestParam.get("under_prefix"));
                    mLedgerMaster.setIsDefaultLedger(false);
                    mLedgerMaster.setIsDeleted(true);
                    mLedgerMaster.setPrinciples(principles);
                    mLedgerMaster.setFoundations(foundations);
                    mLedgerMaster.setBranch(users.getBranch());
                    mLedgerMaster.setCompany(users.getCompany());
                    mLedgerMaster.setLedgerName(object.getName());
//                    mLedgerMaster.setMailingName(employee.getFirstName()+" "+employee.getMiddleName()+" "+employee.getLastName());
//                    mLedgerMaster.setEmployee(employee);
                    mLedgerMaster.setPayhead(object);
                    LedgerMaster newLedger = ledgerMasterRepository.save(mLedgerMaster);
                }
                responseMessage.setMessage("Payhead created successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to create payhead");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to create payhead");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        return responseMessage;
    }

//    public Object DTPayhead(Map<String, String> request, HttpServletRequest httpServletRequest) {
//        Integer from = Integer.parseInt(request.get("from"));
//        Integer to = Integer.parseInt(request.get("to"));
//        String searchText = request.get("searchText");
//        Users user = jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
//        GenericDTData genericDTData = new GenericDTData();
//        List<Payhead> payheadList = new ArrayList<>();
//        List<PayheadDTO> payheadDTOList = new ArrayList<>();
//        try {
//            String query = "SELECT payhead_tbl.id, payhead_tbl.name, payhead_tbl.percentage, payhead_tbl.institute_id, " +
//                    "payhead_tbl.amount, payhead_tbl.created_at, payhead_tbl.created_by, payhead_tbl.is_admin_record, payhead_tbl.payhead_status," +
//                    "payhead_tbl.status, payhead_tbl.updated_at, payhead_tbl.updated_by, payhead_tbl.percentage_of, payhead_tbl.payhead_slug," +
//                    " mst_tbl.name as parent_payhead FROM `payhead_tbl` LEFT JOIN payhead_tbl as mst_tbl ON" +
//                    " mst_tbl.id=payhead_tbl.percentage_of WHERE payhead_tbl.status=1 AND payhead_tbl.is_admin_record=0 AND payhead_tbl.institute_id="+user.getInstitute().getId();
//
//            if (!searchText.equalsIgnoreCase("")) {
//                query = query + " AND (payhead_tbl.name LIKE '%" + searchText + "%' OR mst_tbl.name LIKE '%" +
//                        searchText + "%' OR payhead_tbl.percentage LIKE '%" + searchText + "%')";
//            }
//
//            String jsonToStr = request.get("sort");
//            JsonObject jsonObject = new Gson().fromJson(jsonToStr, JsonObject.class);
//
//            if (!jsonObject.get("colId").toString().equalsIgnoreCase("null") &&
//                    jsonObject.get("colId").toString() != null) {
//                System.out.println(" ORDER BY " + jsonObject.get("colId").toString());
//                String sortBy = jsonObject.get("colId").toString();
//                query = query + " ORDER BY " + sortBy;
//                if (jsonObject.get("isAsc").getAsBoolean()) {
//                    query = query + " ASC";
//                } else {
//                    query = query + " DESC";
//                }
//            }
//            String query1 = query;
//            Integer endLimit = to - from;
//            query = query + " LIMIT " + from + ", " + endLimit;
//            System.out.println("query " + query);
//
//            Query q = entityManager.createNativeQuery(query, Payhead.class);
//            Query q1 = entityManager.createNativeQuery(query1, Payhead.class);
//
//            payheadList = q.getResultList();
//            System.out.println("Limit total rows " + payheadList.size());
//
//            List<Payhead> payheadArrayList = new ArrayList<>();
//            payheadArrayList = q1.getResultList();
//            System.out.println("total rows " + payheadArrayList.size());
//
//            if (payheadList.size() > 0) {
//                for (Payhead payhead : payheadList) {
//                    payheadDTOList.add(convertPayheadToPayheadDTO(payhead));
//                }
//            }
//            genericDTData.setRows(payheadDTOList);
//            genericDTData.setTotalRows(payheadArrayList.size());
//        } catch (Exception e) {
//            e.printStackTrace();
//            System.out.println("Exception " + e.getMessage());
//
//            genericDTData.setRows(payheadDTOList);
//            genericDTData.setTotalRows(0);
//        }
//        return genericDTData;
//    }

    private PayheadDTO convertPayheadToPayheadDTO(Payhead payhead) {
        PayheadDTO payheadDTO = new PayheadDTO();
        payheadDTO.setId(payhead.getId());
        payheadDTO.setName(payhead.getName());
        payheadDTO.setAmount(payhead.getAmount());
        payheadDTO.setPercentage(payhead.getPercentage());
        payheadDTO.setPercentageOf(payhead.getPercentageOf().getId().toString());
        payheadDTO.setIsdeduction(payhead.getIsDeduction());
        payheadDTO.setShowInEmpCreation(payhead.getShowInEmpCreation());
        payheadDTO.setCreatedAt(payhead.getCreatedAt() != null ? payhead.getCreatedAt().toString() : "");
        payheadDTO.setCreatedBy(payhead.getCreatedBy());
        payheadDTO.setUpdatedAt(payhead.getUpdatedAt() != null ? payhead.getUpdatedAt().toString() : "");
        payheadDTO.setUpdatedBy(payhead.getUpdatedBy());
        payheadDTO.setStatus(payhead.getStatus());
        return payheadDTO;
    }

    public JsonObject payheadList(HttpServletRequest request) {
        JsonObject responseMessage = new JsonObject();
        Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray jsonArray = new JsonArray();
        List<Payhead> payheadList = null;
        List<Payhead> defaultPayheadList = null;
        try {
            defaultPayheadList=payheadRepository.findByIsDefaultAndStatus(true,true);
            for (Payhead payhead : defaultPayheadList) {
                JsonObject jsonObject = new JsonObject();
                jsonObject.addProperty("id", payhead.getId());
                jsonObject.addProperty("payheadName", payhead.getName());
                jsonObject.addProperty("percentage", payhead.getPercentage());
                jsonObject.addProperty("amount", payhead.getAmount());
                jsonObject.addProperty("isDefault", payhead.getIsDefault());
                jsonObject.addProperty("percentageOf", payhead.getPercentageOf() != null ? payhead.getPercentageOf().getName() : "");
                jsonArray.add(jsonObject);
            }
            if(user.getUserRole() != null && user.getUserRole().equalsIgnoreCase("CADMIN")) {
                payheadList = payheadRepository.findByCompanyIdAndStatus(user.getCompany().getId(), true);
            } else if(user.getUserRole() != null && user.getUserRole().equalsIgnoreCase("BADMIN")) {
                payheadList = payheadRepository.findByCompanyIdAndBranchIdAndStatus(user.getCompany().getId(), user.getBranch().getId(), true);
            }
            if(payheadList != null) {
                for (Payhead payhead : payheadList) {
                    JsonObject jsonObject = new JsonObject();
                    jsonObject.addProperty("id", payhead.getId());
                    jsonObject.addProperty("payheadName", payhead.getName());
                    jsonObject.addProperty("percentage", payhead.getPercentage());
                    jsonObject.addProperty("amount", payhead.getAmount());
                    jsonObject.addProperty("isDefault", payhead.getIsDefault());
                    jsonObject.addProperty("percentageOf", payhead.getPercentageOf() != null ? payhead.getPercentageOf().getName() : "");
                    jsonArray.add(jsonObject);
                }
                responseMessage.add("response", jsonArray);
                responseMessage.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("response", "Data not found");
                responseMessage.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            responseMessage.addProperty("response", "Failed to load data");
            responseMessage.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject findPayhead(Map<String, String> request) {
        JsonObject result = new JsonObject();
        JsonObject jsonObject = new JsonObject();
        try {
            Long payheadId = Long.parseLong(request.get("id"));
            Payhead payhead = payheadRepository.findByIdAndStatus(payheadId, true);
            if (payhead != null) {
                jsonObject.addProperty("id",payhead.getId());
                jsonObject.addProperty("name",payhead.getName());
                jsonObject.addProperty("amount",payhead.getAmount());
                jsonObject.addProperty("percentage",payhead.getPercentage());
                jsonObject.addProperty("percentageOf",payhead.getPercentageOf().getId().toString());
                jsonObject.addProperty("isDeduction",payhead.getIsDeduction());
                jsonObject.addProperty("showInEmpCreation",payhead.getShowInEmpCreation());
                jsonObject.addProperty("status",payhead.getStatus());
                LedgerMaster mLedger = ledgerMasterRepository.findByPayheadIdAndStatus(payhead.getId(), true);
                if(mLedger != null){
                    if (mLedger.getOpeningBalType() != null)
                        jsonObject.addProperty("opening_bal_type", mLedger.getOpeningBalType());
                    if (mLedger.getPrincipleGroups() != null) {
                        jsonObject.addProperty("principle_id", mLedger.getPrinciples().getId());
                        jsonObject.addProperty("principle_name", mLedger.getPrinciples().getPrincipleName());
                    } else {
                        jsonObject.addProperty("principle_id", mLedger.getPrinciples().getId());
                        jsonObject.addProperty("principle_name", mLedger.getPrinciples().getPrincipleName());
                    }
                }
                result.addProperty("message", "success");
                result.addProperty("responseStatus", HttpStatus.OK.value());
                result.add("response", jsonObject);
            } else {
                result.addProperty("message", "Not Found");
                result.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            result.addProperty("response", "Failed to load data");
            result.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return result;
    }

    public Object updatePayhead(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Long id = Long.valueOf(requestParam.get("id"));
        Payhead payhead = payheadRepository.findByIdAndStatus(id, true);
        if (payhead != null) {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            try {
                if(requestParam.containsKey("payheadName"))
                    payhead.setName(requestParam.get("payheadName"));
                if(requestParam.containsKey("percentage"))
                    payhead.setPercentage(Double.parseDouble(requestParam.get("percentage")));
                if(requestParam.containsKey("status"))
                    payhead.setStatus(Boolean.parseBoolean(requestParam.get("status")));
                if(requestParam.containsKey("is_dedcution"))
                    payhead.setIsDeduction(Boolean.parseBoolean(requestParam.get("is_dedcution")));
                if(requestParam.containsKey("show_in_emp_creation"))
                    payhead.setShowInEmpCreation(Boolean.parseBoolean(requestParam.get("show_in_emp_creation")));
                if(requestParam.containsKey("payheadId")) {
                    if (requestParam.get("payheadId") != null) {
                        Long payheadId = Long.valueOf(requestParam.get("payheadId"));
                        Payhead payhead1 = payheadRepository.findByIdAndStatus(payheadId, true);
                        payhead.setPercentageOf(payhead1);
                    }
                }
                payhead.setUpdatedBy(users.getId());
                payhead.setUpdatedAt(LocalDateTime.now());
                try {
                    payheadRepository.save(payhead);
                    responseMessage.setMessage("Payhead updated successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception " + e.getMessage());
                    responseMessage.setMessage("Failed to update payhead");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to update payhead");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } else {
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }

    public Object deletePayhead(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Long id = Long.valueOf(requestParam.get("id"));
        Payhead payhead = payheadRepository.findByIdAndStatus(id, true);
        if (payhead != null) {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            try {
                payhead.setUpdatedBy(users.getId());
                payhead.setUpdatedAt(LocalDateTime.now());
                payhead.setStatus(false);
                try {
                    payheadRepository.save(payhead);
                    responseMessage.setMessage("Payhead deleted successfully");
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Exception " + e.getMessage());
                    responseMessage.setMessage("Failed to delete payhead");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to delete payhead");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } else {
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }

        return responseMessage;
    }

    public JsonObject getpayheadList(HttpServletRequest request){
        JsonArray result =new JsonArray();
        Users users= jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<Payhead> payheadList=new ArrayList<>();
        payheadList = payheadRepository.findAllBystatus();
        for(Payhead payhead:payheadList){
            try{
                JsonObject response=new JsonObject();
                response.addProperty("id",payhead.getId());
                response.addProperty("name",payhead.getName());
                response.addProperty("status",payhead.getStatus());
                result.add(response);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        JsonObject output=new JsonObject();
        output.addProperty("message","success");
        output.addProperty("responseStatus",HttpStatus.OK.value());
        output.add("data",result);
        return output;
    }
}
