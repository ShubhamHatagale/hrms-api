package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.config.AppConfig;
import com.opethic.hrms.HRMSNew.config.SystemConfigParameter;
import com.opethic.hrms.HRMSNew.exception.ApiException;
import com.opethic.hrms.HRMSNew.fileConfig.FileStorageProperties;
import com.opethic.hrms.HRMSNew.fileConfig.FileStorageService;
import com.opethic.hrms.HRMSNew.models.master.Company;
import com.opethic.hrms.HRMSNew.models.master.GstTypeMaster;
import com.opethic.hrms.HRMSNew.models.master.Users;
import com.opethic.hrms.HRMSNew.repositories.config.AppConfigRepository;
import com.opethic.hrms.HRMSNew.repositories.config.SystemConfigParameterRepository;
import com.opethic.hrms.HRMSNew.repositories.master.*;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.persistence.Column;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


@Service
public class CompanyService {
    private static final Logger companyLogger = LogManager.getLogger(CompanyService.class);
    @Autowired
    private CompanyRepository companyRepository;
    @Autowired
    private CityRepository cityRepository;
    @Autowired
    private StateRepository stateRepository;
    @Autowired
    private CountryRepository countryRepository;
    @Autowired
    private FileStorageService fileStorageService;
    @Autowired
    private UsersRepository usersRepository;
    @Autowired
    private PasswordEncoder bcryptEncoder;

    @Autowired
    private GstTypeMasterRepository gstMasterRepository;

    @Autowired
    private  JwtTokenUtil jwtTokenUtil;
    @Autowired
    private SystemConfigParameterRepository systemConfigParameterRepository;
    @Autowired
    private AppConfigRepository appConfigRepository;
    @Autowired
    Utility utility;
    @Transactional
    public Object createCompany(MultipartHttpServletRequest request, Users users) {
        JsonObject response = new JsonObject();
        FileStorageProperties fileStorageProperties = new FileStorageProperties();
        if (validateDuplicateCompany(request.getParameter("companyName"))) {
            response.addProperty("message", "Company with this name is already exist");
            response.addProperty("status", HttpStatus.CONFLICT.value());
        } else {
            try {
                Map<String, String[]> paramMap = request.getParameterMap();
                Company company = new Company();
                company.setCompanyName(request.getParameter("companyName"));
                company.setCompanyType(request.getParameter("companyType"));
                if (paramMap.containsKey("companyCode"))
                    company.setCompanyCode(request.getParameter("companyCode"));
                if (paramMap.containsKey("mobileNumber"))
                    company.setMobileNumber(Long.parseLong(request.getParameter("mobileNumber")));
                if (paramMap.containsKey("whatsappNumber"))
                    company.setWhatsappNumber(Long.parseLong(request.getParameter("whatsappNumber")));
                if (paramMap.containsKey("emailId"))
                    company.setEmailId(request.getParameter("emailId"));
                if (paramMap.containsKey("websiteUrl"))
                    company.setWebsiteUrl(request.getParameter("websiteUrl"));
                if (paramMap.containsKey("regAddress"))
                    company.setRegAddress(request.getParameter("regAddress"));
                if (paramMap.containsKey("regPincode"))
                    company.setRegPincode(request.getParameter("regPincode"));
                if (paramMap.containsKey("regArea"))
                    company.setRegArea(request.getParameter("regArea"));
                if (paramMap.containsKey("regCityId"))
                    company.setRegCityId(Long.valueOf(request.getParameter("regCityId")));
                if (paramMap.containsKey("regStateId"))
                    company.setRegStateId(Long.valueOf(request.getParameter("regStateId")));
                if (paramMap.containsKey("regCountryId"))
                    company.setRegCountryId(Long.valueOf(request.getParameter("regCountryId")));
                if (paramMap.containsKey("sameAsRegisterAddress"))
                    company.setSameAsRegisterAddress(Boolean.parseBoolean(request.getParameter("sameAsRegisterAddress")));
                if (paramMap.containsKey("corpAddress"))
                    company.setCorpAddress(request.getParameter("corpAddress"));
                if (paramMap.containsKey("corpPincode"))
                    company.setCorpPincode(request.getParameter("corpPincode"));
                if (paramMap.containsKey("corpArea"))
                    company.setCorpArea(request.getParameter("corpArea"));
                if (paramMap.containsKey("corpCityId"))
                    company.setCorpCityId(Long.valueOf(request.getParameter("corpCityId")));
                if (paramMap.containsKey("corpStateId"))
                    company.setCorpStateId(Long.valueOf(request.getParameter("corpStateId")));
                if (paramMap.containsKey("corpCountryId"))
                    company.setCorpCountryId(Long.valueOf(request.getParameter("corpCountryId")));
                if (paramMap.containsKey("licenseNo"))
                    company.setLicenseNo(request.getParameter("licenseNo"));
                if (paramMap.containsKey("licenseExpiryDate"))
                    company.setLicenseExpiryDate(LocalDate.parse(request.getParameter("licenseExpiryDate")));
                if (paramMap.containsKey("holidayFromDate"))
                    company.setHolidayFromDate(LocalDate.parse(request.getParameter("holidayFromDate")));
                if (paramMap.containsKey("holidayToDate"))
                    company.setHolidayToDate(LocalDate.parse(request.getParameter("holidayToDate")));
                if (paramMap.containsKey("websiteUrl"))
                    company.setWebsiteUrl(request.getParameter("websiteUrl"));
                company.setCurrency(request.getParameter("currency"));
                company.setGstApplicable(false);
                if (Boolean.parseBoolean(request.getParameter("gstApplicable"))) {
                    company.setGstApplicable(true);
                    company.setGstNumber(request.getParameter("gstNumber"));
                    company.setGstTypeId(Long.valueOf(request.getParameter("gstTypeId")));
                    if (paramMap.containsKey("gstApplicableDate"))
                        company.setGstApplicableDate(LocalDate.parse(request.getParameter("gstApplicableDate")));
                }

                if(paramMap.containsKey("isCompanyEsic"))
                    company.setIsCompanyEsic(Boolean.valueOf(request.getParameter("isCompanyEsic")));
                if(paramMap.containsKey("isCompanyPf"))
                    company.setIsCompanyPf(Boolean.valueOf(request.getParameter("isCompanyPf")));
                if(paramMap.containsKey("pfRegistrationNumber"))
                    company.setPfRegistrationNumber(request.getParameter("pfRegistrationNumber"));
                if(paramMap.containsKey("isCompanyPt"))
                    company.setIsCompanyPt(Boolean.valueOf(request.getParameter("isCompanyPt")));
                if(paramMap.containsKey("ptRegistrationNumber"))
                    company.setPtRegistrationNumber(request.getParameter("ptRegistrationNumber"));
                company.setCreatedBy(users.getId());
                company.setStatus(true);

                if(request.getParameterMap().containsKey("companyLogo")) {
                    if (request.getFile("companyLogo") != null) {
                        MultipartFile image = request.getFile("companyLogo");
                        fileStorageProperties.setUploadDir("." + File.separator + "company" + File.separator + "company" + File.separator);
                        String imagePath = fileStorageService.storeFile(image, fileStorageProperties);
                        if (imagePath != null) {
                            company.setCompanyLogo(File.separator + "company" + File.separator + "company" + File.separator + imagePath);
                        } else {
                            response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
                            response.addProperty("message","Failed to upload image. Please try again!");
                            return response;
                        }
                    }
                }
                Company savedCompany = companyRepository.save(company);
                if(savedCompany != null) {
                    /**** Company Admin Creation *****/
                    try {
                        Users companyUser = new Users();
                        if (paramMap.containsKey("adminMobileNumber"))
                            companyUser.setMobileNumber(Long.valueOf(request.getParameter("adminMobileNumber")));
                        if (paramMap.containsKey("adminEmailId"))
                            companyUser.setEmailId(request.getParameter("adminEmailId"));
                        if (paramMap.containsKey("fullName"))
                            companyUser.setFullName(request.getParameter("fullName"));
                        companyUser.setUsercode(request.getParameter("username"));
                        companyUser.setUsername(request.getParameter("username"));
                        companyUser.setUserRole("cadmin");
                        companyUser.setStatus(true);
                        companyUser.setIsSuperAdmin(false);
                        companyUser.setIsAdmin(true);
                        companyUser.setCreatedBy(users.getId());
                        companyUser.setPassword(bcryptEncoder.encode(request.getParameter("password")));
                        companyUser.setPlainPassword(request.getParameter("password"));
                        companyUser.setCompany(savedCompany);
                        Users savedAdmin = usersRepository.save(companyUser);
                        if(savedAdmin != null){
                            String strJson = request.getParameter("configData");
                            if(strJson != null && strJson.length() > 0) {
                                JsonArray settingArray = new JsonParser().parse(strJson).getAsJsonArray();
                                for (JsonElement jsonElement : settingArray) {
                                    JsonObject object = jsonElement.getAsJsonObject();
                                    AppConfig appConfig = new AppConfig();
                                    SystemConfigParameter systemConfigParameter =
                                            systemConfigParameterRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
                                    appConfig.setSystemConfigParameter(systemConfigParameter);

                                    appConfig.setConfigName(object.get("slug").getAsString());
                                    appConfig.setConfigValue(object.get("value").getAsBoolean() == true ? 1 : 0);
                                    appConfig.setConfigLabel(object.get("display_name").getAsString());
                                    appConfig.setBranch(users.getBranch());
                                    appConfig.setCompany(savedCompany);
                                    appConfig.setCreatedBy(users.getId());
                                    appConfig.setUpdatedBy(users.getId());
                                    appConfig.setStatus(true);
                                    AppConfig mAppConfig = appConfigRepository.save(appConfig);
                                    if (mAppConfig != null) {
                                        response.addProperty("message", "Company created successfully");
                                        response.addProperty("companyId", savedCompany.getId());
                                        response.addProperty("status", HttpStatus.OK.value());
                                    } else {
                                        response.addProperty("message", "Trouble while creating app config");
                                        response.addProperty("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
                                    }
                                }
                            } else {
                                response.addProperty("message", "Failed to add config data while creating company");
                                response.addProperty("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
                            }
                        } else {
                            response.addProperty("message", "Trouble while creating company admin");
                            response.addProperty("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
                        }
                    } catch (Exception e) {
                        companyLogger.error("createCompany::admin::" + e);
                        throw new ApiException("Failed to create company admin while create company");
                    }
                } else {
                    response.addProperty("message", "Company creation failed");
                    response.addProperty("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } catch (Exception e) {
                companyLogger.error("createCompany::save" + e);
                throw new ApiException("Failed to create company");
            }
        }
        return response;
    }

    private Boolean validateDuplicateCompany(String companyName) {
        Company company = companyRepository.findByCompanyNameIgnoreCaseAndStatus(companyName, true);
        return company != null;
    }

    public JsonObject findCompany(Map<String, String> jsonRequest) {
        JsonObject responseMessage = new JsonObject();
        Long companyId = Long.parseLong(jsonRequest.get("id"));
        try {
            Company company = companyRepository.findByIdAndStatus(companyId, true);
            if (company != null) {
                JsonObject jsonObject = new JsonObject();
                JsonArray configArray = new JsonArray();
                jsonObject.addProperty("company_id", company.getId());
                jsonObject.addProperty("companyCode", company.getCompanyCode());
                jsonObject.addProperty("companyName", company.getCompanyName());
                jsonObject.addProperty("companyType", company.getCompanyType());
                jsonObject.addProperty("companyLogo", company.getCompanyLogo());
                jsonObject.addProperty("regAddress", company.getRegAddress());
                jsonObject.addProperty("regPincode", company.getRegPincode());
                jsonObject.addProperty("regArea", company.getRegArea());
                jsonObject.addProperty("regCityId", company.getRegCityId());
                jsonObject.addProperty("regStateId", company.getRegStateId());
                jsonObject.addProperty("regCountryId", company.getRegCountryId());
                jsonObject.addProperty("sameAsRegisterAddress", company.getSameAsRegisterAddress());
                jsonObject.addProperty("corpAddress", company.getCorpAddress());
                jsonObject.addProperty("corpPincode", company.getCorpPincode());
                jsonObject.addProperty("corpArea", company.getCorpArea());
                jsonObject.addProperty("corpCityId", company.getCorpCityId());
                jsonObject.addProperty("corpStateId", company.getCorpStateId());
                jsonObject.addProperty("corpCountryId", company.getCorpCountryId());
                jsonObject.addProperty("licenseNo", company.getLicenseNo());
                jsonObject.addProperty("licenseExpiryDate", company.getLicenseExpiryDate() != null ? company.getLicenseExpiryDate().toString() :"");
                jsonObject.addProperty("holidayFromDate",company.getHolidayFromDate()!=null?company.getHolidayFromDate().toString():"");
                jsonObject.addProperty("holidayToDate",company.getHolidayToDate()!=null?company.getHolidayToDate().toString():"");
                jsonObject.addProperty("websiteUrl", company.getWebsiteUrl());
                jsonObject.addProperty("emailId", company.getEmailId());
                jsonObject.addProperty("mobileNumber", company.getMobileNumber());
                jsonObject.addProperty("whatsappNumber", company.getWhatsappNumber());
                jsonObject.addProperty("currency", company.getCurrency());
                jsonObject.addProperty("gstApplicable", company.getGstApplicable());
                jsonObject.addProperty("gstNumber", company.getGstNumber());
                jsonObject.addProperty("gstTypeId", company.getGstTypeId());
                jsonObject.addProperty("gstApplicableDate", company.getGstApplicableDate() != null ? company.getGstApplicableDate().toString() : "");
                jsonObject.addProperty("isCompanyEsic", company.getIsCompanyEsic());
                jsonObject.addProperty("isCompanyPf", company.getIsCompanyPf());
                jsonObject.addProperty("pfRegistrationNumber", company.getPfRegistrationNumber());
                jsonObject.addProperty("isCompanyPt", company.getIsCompanyPt());
                jsonObject.addProperty("ptRegistrationNumber", company.getPtRegistrationNumber());
                jsonObject.addProperty("status", company.getStatus());
                List<AppConfig> configs = appConfigRepository.findByCompanyIdAndStatusAndBranchIsNull(company.getId(), true);
                if(configs != null && configs.size() > 0){
                    for(AppConfig config : configs) {
                        SystemConfigParameter systemConfigParameter =
                                systemConfigParameterRepository.findByIdAndStatus(config.getSystemConfigParameter().getId(), true);

                        JsonObject configObject = new JsonObject();
                        configObject.addProperty("id", config.getId());
                        configObject.addProperty("display_name", systemConfigParameter.getDisplayName());
                        configObject.addProperty("slug", systemConfigParameter.getSlug());
                        configObject.addProperty("is_label", systemConfigParameter.getIsLabel());
                        configObject.addProperty("value",config.getConfigValue()==1?true:false);
                        configObject.addProperty("status", config.getStatus());
                        configArray.add(configObject);
                    }
                }
                Users user = usersRepository.findByCompanyIdAndUserRoleAndStatus(company.getId(), "cadmin",true);
                if(user != null){
                    JsonObject companyUser = new JsonObject();
                    companyUser.addProperty("fullname", user.getFullName());
                    companyUser.addProperty("email", user.getEmailId());
                    companyUser.addProperty("mobile", user.getMobileNumber());
                    companyUser.addProperty("username", user.getUsername());
                    companyUser.addProperty("password", user.getPlainPassword());
                    jsonObject.add("user",companyUser);
                }
                jsonObject.add("configArray",configArray);
                responseMessage.add("response",jsonObject);
                responseMessage.addProperty("responseStatus",HttpStatus.OK.value());
            } else {
                responseMessage.addProperty("message","Data not found");
                responseMessage.addProperty("response",HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            responseMessage.addProperty("message","Data not found");
            responseMessage.addProperty("response",HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public JsonObject listOfCompany(HttpServletRequest httpServletRequest) {
        Users users = jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<Company> companyList = null;
        Company company1;
        try {
            if(users.getIsSuperAdmin()) {
                companyList = companyRepository.findAllByStatus(true);
                for (Company company : companyList) {
                    JsonObject object = new JsonObject();
                    object.addProperty("id", company.getId());
                    object.addProperty("companyName", company.getCompanyName());
                    object.addProperty("mobileNumber", company.getMobileNumber());
                    object.addProperty("createdAt", company.getCreatedAt().toString());
                    jsonArray.add(object);
                }
            } else {
                company1 = companyRepository.findByIdAndStatus(users.getCompany().getId(), true);
                JsonObject object = new JsonObject();
                object.addProperty("id", company1.getId());
                object.addProperty("companyName", company1.getCompanyName());
                object.addProperty("mobileNumber", company1.getMobileNumber());
                object.addProperty("createdAt", company1.getCreatedAt().toString());
                jsonArray.add(object);
            }
            response.add("response", jsonArray);
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object deleteCompany(Map<String, String> jsonRequest, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Company company = companyRepository.findByIdAndStatus(Long.parseLong(jsonRequest.get("id")),
                    true);
            if (company != null) {
                company.setStatus(false);
                company.setUpdatedBy(users.getId());
                company.setUpdatedAt(LocalDateTime.now());
                try {
                    companyRepository.save(company);
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                    responseMessage.setMessage("Company deleted successfully");
                } catch (Exception e) {
                    System.out.println("Exception " + e.getMessage());
                    responseMessage.setMessage("Failed to delete company");
                    responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } else {
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
                responseMessage.setMessage("Data not found");
            }
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Failed to delete company");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object updateCompany(MultipartHttpServletRequest request) {
        Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        Map<String, String[]> paramMap = request.getParameterMap();
        FileStorageProperties fileStorageProperties = new FileStorageProperties();
//        if (validateDuplicateCompany(request.getParameter("companyName"))) {
//            response.addProperty("message", "Company with this name is already exist");
//            response.addProperty("status", HttpStatus.CONFLICT.value());
//        } else {
            try {
                Company company = companyRepository.findByIdAndStatus(Long.parseLong(request.getParameter("id")), true);
                company.setCompanyName(request.getParameter("companyName"));
                company.setCompanyType(request.getParameter("companyType"));
                if (paramMap.containsKey("companyCode"))
                    company.setCompanyCode(request.getParameter("companyCode"));
                if (paramMap.containsKey("mobileNumber"))
                    company.setMobileNumber(Long.parseLong(request.getParameter("mobileNumber")));
                if (paramMap.containsKey("whatsappNumber"))
                    company.setWhatsappNumber(Long.parseLong(request.getParameter("whatsappNumber")));
                if (paramMap.containsKey("emailId"))
                    company.setEmailId(request.getParameter("emailId"));
                if (paramMap.containsKey("websiteUrl"))
                    company.setWebsiteUrl(request.getParameter("websiteUrl"));
                if (paramMap.containsKey("regAddress"))
                    company.setRegAddress(request.getParameter("regAddress"));
                if (paramMap.containsKey("regPincode"))
                    company.setRegPincode(request.getParameter("regPincode"));
                if (paramMap.containsKey("regArea"))
                    company.setRegArea(request.getParameter("regArea"));
                if (paramMap.containsKey("regCityId"))
                    company.setRegCityId((!request.getParameter("regCityId").isEmpty() && request.getParameter("regCityId") != null) ? Long.valueOf(request.getParameter("regCityId")) : null);
                if (paramMap.containsKey("regStateId"))
                    company.setRegStateId((!request.getParameter("regStateId").isEmpty() && request.getParameter("regStateId") != null) ? Long.valueOf(request.getParameter("regStateId")) : null);
                if (paramMap.containsKey("regCountryId"))
                    company.setRegCountryId((!request.getParameter("regCountryId").isEmpty() && request.getParameter("regCountryId") != null) ? Long.valueOf(request.getParameter("regCountryId")) : null);
                if (paramMap.containsKey("sameAsRegisterAddress"))
                    company.setSameAsRegisterAddress(Boolean.parseBoolean(request.getParameter("sameAsRegisterAddress")));
                if (paramMap.containsKey("corpAddress"))
                    company.setCorpAddress(request.getParameter("corpAddress"));
                if (paramMap.containsKey("corpPincode"))
                    company.setCorpPincode(request.getParameter("corpPincode"));
                if (paramMap.containsKey("corpArea"))
                    company.setCorpArea(request.getParameter("corpArea"));
                if (paramMap.containsKey("corpCityId"))
                    company.setCorpCityId((!request.getParameter("corpCityId").isEmpty() && request.getParameter("corpCityId") != null) ? Long.valueOf(request.getParameter("corpCityId")):null);
                if (paramMap.containsKey("corpStateId"))
                    company.setCorpStateId((!request.getParameter("corpStateId").isEmpty() && request.getParameter("corpStateId") != null) ? Long.valueOf(request.getParameter("corpStateId")) : null);
                if (paramMap.containsKey("corpCountryId"))
                    company.setCorpCountryId((!request.getParameter("corpCountryId").isEmpty() && request.getParameter("corpCountryId") != null) ? Long.valueOf(request.getParameter("corpCountryId")) : null);
                if (paramMap.containsKey("licenseNo"))
                    company.setLicenseNo(request.getParameter("licenseNo"));
                if (paramMap.containsKey("licenseExpiryDate"))
                    company.setLicenseExpiryDate(LocalDate.parse(request.getParameter("licenseExpiryDate")));
                if (paramMap.containsKey("holidayFromDate"))
                    company.setHolidayFromDate(LocalDate.parse(request.getParameter("holidayFromDate")));
                if (paramMap.containsKey("holidayToDate"))
                    company.setHolidayToDate(LocalDate.parse(request.getParameter("holidayToDate")));
                if (paramMap.containsKey("websiteUrl"))
                    company.setWebsiteUrl(request.getParameter("websiteUrl"));
                company.setCurrency(request.getParameter("currency"));
                company.setGstApplicable(false);
                if (Boolean.parseBoolean(request.getParameter("gstApplicable"))) {
                    company.setGstApplicable(true);
                    company.setGstNumber(request.getParameter("gstNumber"));
                    company.setGstTypeId(request.getParameter("gstTypeId") != null ? Long.valueOf(request.getParameter("gstTypeId")) : null);
                    if (paramMap.containsKey("gstApplicableDate"))
                        company.setGstApplicableDate(LocalDate.parse(request.getParameter("gstApplicableDate")));
                }

                if(paramMap.containsKey("isCompanyEsic"))
                    company.setIsCompanyEsic(Boolean.valueOf(request.getParameter("isCompanyEsic")));
                if(paramMap.containsKey("isCompanyPf"))
                    company.setIsCompanyPf(Boolean.valueOf(request.getParameter("isCompanyPf")));
                if(paramMap.containsKey("pfRegistrationNumber"))
                    company.setPfRegistrationNumber(request.getParameter("pfRegistrationNumber") != null ? request.getParameter("pfRegistrationNumber") : null);
                if(paramMap.containsKey("isCompanyPt"))
                    company.setIsCompanyPt(Boolean.valueOf(request.getParameter("isCompanyPt")));
                if(paramMap.containsKey("ptRegistrationNumber"))
                    company.setPtRegistrationNumber(request.getParameter("ptRegistrationNumber") != null ? request.getParameter("ptRegistrationNumber") : null);
                company.setCreatedBy(users.getId());
                company.setStatus(true);
                company.setUpdatedBy(users.getId());
                if(request.getParameterMap().containsKey("companyLogo")) {
                    if (request.getFile("companyLogo") != null) {
                        MultipartFile image = request.getFile("companyLogo");
                        fileStorageProperties.setUploadDir("." + File.separator + "company" + File.separator + "company" + File.separator);
                        String imagePath = fileStorageService.storeFile(image, fileStorageProperties);
                        if (imagePath != null) {
                            company.setCompanyLogo(File.separator + "company" + File.separator + "company" + File.separator + imagePath);
                        } else {
                            response.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
                            response.addProperty("message","Failed to upload image. Please try again!");
                            return response;
                        }
                    }
                }
                Company savedCompany = companyRepository.save(company);
                /**** Company Admin Update *****/
                if(savedCompany != null) {
                    try {
                        Users companyUser = usersRepository.findByCompanyIdAndBranchIsNullAndStatus(savedCompany.getId(), true);
                        if (paramMap.containsKey("adminMobileNumber"))
                            companyUser.setMobileNumber(Long.valueOf(request.getParameter("adminMobileNumber")));
                        if (paramMap.containsKey("adminEmailId"))
                            companyUser.setEmailId(request.getParameter("adminEmailId"));
                        if (paramMap.containsKey("fullName"))
                            companyUser.setFullName(request.getParameter("fullName"));
                        if (paramMap.containsKey("username")) {
                            companyUser.setUsercode(request.getParameter("username"));
                            companyUser.setUsername(request.getParameter("username"));
                        }
                        if (paramMap.containsKey("admin"))
                            companyUser.setUserRole("admin");
                        if (paramMap.containsKey("status"))
                            companyUser.setStatus(Boolean.parseBoolean(request.getParameter("status")));
                        companyUser.setIsSuperAdmin(false);
                        if (paramMap.containsKey("isAdmin"))
                            companyUser.setIsAdmin(Boolean.parseBoolean(paramMap.get("isAdmin").toString()));
                        companyUser.setCreatedBy(users.getId());
                        if (paramMap.containsKey("password")) {
                            companyUser.setPassword(bcryptEncoder.encode(request.getParameter("password")));
                            companyUser.setPlainPassword(request.getParameter("password"));
                        }
                        companyUser.setCompany(savedCompany);
                        Users savedAdmin = usersRepository.save(companyUser);
                        if(savedAdmin != null){
                            String strJson = request.getParameter("configData");
                            if(strJson != null && strJson.length() > 0) {
                                JsonArray settingArray = new JsonParser().parse(strJson).getAsJsonArray();
                                for (JsonElement jsonElement : settingArray) {
                                    JsonObject object = jsonElement.getAsJsonObject();
                                    AppConfig appConfig = appConfigRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
                                    SystemConfigParameter systemConfigParameter =
                                            systemConfigParameterRepository.findByIdAndStatus(appConfig.getSystemConfigParameter().getId(), true);
                                    appConfig.setSystemConfigParameter(systemConfigParameter);
                                    appConfig.setConfigName(object.get("slug").getAsString());
                                    appConfig.setConfigValue(object.get("value").getAsBoolean() == true ? 1 : 0);
                                    appConfig.setConfigLabel(object.get("display_name").getAsString());
                                    appConfig.setBranch(users.getBranch());
                                    appConfig.setCompany(savedCompany);
                                    appConfig.setCreatedBy(users.getId());
                                    appConfig.setUpdatedBy(users.getId());
                                    appConfig.setStatus(true);
                                    AppConfig mAppConfig = appConfigRepository.save(appConfig);
                                    if (mAppConfig != null) {
                                        response.addProperty("message", "Company Updated successfully");
                                        response.addProperty("companyId", savedCompany.getId());
                                        response.addProperty("status", HttpStatus.OK.value());
                                    } else {
                                        response.addProperty("message", "Trouble while updating app config");
                                        response.addProperty("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
                                    }
                                }
                            } else {
                                response.addProperty("message", "Company Updated successfully with empty config");
                                response.addProperty("status", HttpStatus.OK.value());
                            }
                        } else {
                            response.addProperty("message", "Company Updated successfully with no admin data");
                            response.addProperty("status", HttpStatus.OK.value());
                        }
                    } catch (Exception e) {
                        companyLogger.error("createCompany::admin::" + e);
                        throw new ApiException("Failed to update company admin while updating company");
                    }
                } else {
                    response.addProperty("message", "Company update failed");
                    response.addProperty("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                response.addProperty("message","Failed to Update Company");
                response.addProperty("status",HttpStatus.BAD_REQUEST.value());
            }
//        }
        return response;
    }

    public JsonObject getGstType() {
        JsonObject res = new JsonObject();
        JsonArray result = new JsonArray();
        List<GstTypeMaster> list = new ArrayList<>();
        list = gstMasterRepository.findAll();
        if (list.size() > 0) {
            for (GstTypeMaster mList : list) {
                if (mList.getId() != 3) {
                    JsonObject response = new JsonObject();
                    response.addProperty("id", mList.getId());
                    response.addProperty("gstType", mList.getGstType());
                    result.add(response);
                }
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
}
