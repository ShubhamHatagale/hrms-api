package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.dto.EmployeeDTO;
import com.opethic.hrms.HRMSNew.fileConfig.FileStorageProperties;
import com.opethic.hrms.HRMSNew.fileConfig.FileStorageService;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.master.*;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import com.opethic.hrms.HRMSNew.util.Utility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;
import java.io.File;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class EmployeeService {

    @Autowired
    EmployeeRepository employeeRepository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    private DesignationRepository designationRepository;
    @Autowired
    private ShiftRepository shiftRepository;
    @Autowired
    private CompanyRepository companyRepository;
    @Autowired
    private BranchRepository branchRepository;
    @Autowired
    JwtTokenUtil jwtTokenUtil;
    @Autowired
    private FileStorageService fileStorageService;
    @Autowired
    DocumentRepository documentRepository;
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private Utility utility;
    @Autowired
    private PrincipleGroupsRepository principleGroupsRepository;
    @Autowired
    private BalancingMethodRepository balancingMethodRepository;
    @Autowired
    private LedgerMasterRepository ledgerMasterRepository;
    @Autowired
    private EmployeeFamilyRepository employeeFamilyRepository;
    @Autowired
    private EmployeeEducationRepository employeeEducationRepository;
    @Autowired
    private EmployeeDocumentRepository employeeDocumentRepository;
    @Autowired
    private EmployeeExperienceRepository employeeExperienceRepository;
    @Autowired
    private EmployeeReferenceRepository employeeReferenceRepository;
    @Autowired
    private LevelRepository levelRepository;
    @Autowired
    private PayheadRepository payheadRepository;
    @Autowired
    private UsersRepository usersRepository;
    @Autowired
    private DepartmentRepository departmentRepository;

    @Transactional
    public Object createEmployee(MultipartHttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        FileStorageProperties fileStorageProperties = new FileStorageProperties();
        try {
            Employee emp = employeeRepository.findByMobileNumberAndStatus(Long.parseLong(request.getParameter("mobileNumber")), true);
            if(emp != null) {
                responseObject.setMessage("Duplicate mobile number");
                responseObject.setResponseStatus(HttpStatus.FORBIDDEN.value());
            } else {
                Employee employee = new Employee();
                List<EmployeePayhead> employeePayheadList = new ArrayList<>();
                List<Payhead> payheads = payheadRepository.getDefaultPayheads();
                for(Payhead payhead : payheads){
                    EmployeePayhead employeePayhead = new EmployeePayhead();
                    if(payhead.getIsDefault()) {
                        employeePayhead.setPayhead(payhead);
                        employeePayheadList.add(employeePayhead);
                    }
                }

                employee.setFirstName(request.getParameter("firstName"));
                employee.setMiddleName(request.getParameter("middleName"));
                employee.setLastName(request.getParameter("lastName"));
                employee.setFullName(request.getParameter("firstName")+" "+request.getParameter("middleName")+" "+request.getParameter("lastName"));
//            employee.setAddress(request.getParameter("fullAddress"));
                employee.setPresentAddress(request.getParameter("presentAddress"));
                employee.setPermanentAddress(request.getParameter("permanentAddress"));
                employee.setCorrespondenceAddress(request.getParameter("correspondenceAddress"));
                employee.setMobileNumber(Long.parseLong(request.getParameter("mobileNumber")));
                employee.setDob(LocalDate.parse(request.getParameter("dob")));
                employee.setAge(Integer.parseInt(request.getParameter("age")));
                employee.setReligion(request.getParameter("religion"));
                employee.setCast(request.getParameter("cast"));
                employee.setReasonToJoin(request.getParameter("reasonToJoin"));
                employee.setMarriageStatus(request.getParameter("marriageStatus"));
                if(request.getParameterMap().containsKey("emergencyRelation"))
                    employee.setEmergencyRelation(request.getParameter("emergencyRelation"));
                if(request.getParameterMap().containsKey("emergencyContact"))
                    employee.setEmergencyContact(request.getParameter("emergencyContact"));
                if (request.getParameter("height") != null && !request.getParameter("height").equalsIgnoreCase("NA"))
                    employee.setHeight(Double.parseDouble(request.getParameter("height")));
                if (request.getParameter("weight") != null && !request.getParameter("weight").equalsIgnoreCase("NA"))
                    employee.setWeight(Double.parseDouble(request.getParameter("weight")));
                employee.setBloodGroup(request.getParameter("bloodGroup"));
//            employee.setIsSpecks(Boolean.parseBoolean(request.getParameter("isSpecks")));
                employee.setEmployeeType(request.getParameter("employeeType"));

                employee.setIsExperienceEmployee(request.getParameter("isExperienceEmployee").equalsIgnoreCase("true"));

                if (request.getParameter("isDisability").equalsIgnoreCase("true")) {
                    employee.setIsDisability(true);
                    employee.setDisabilityDetails(request.getParameter("disabilityDetails"));
                } else {
                    employee.setIsDisability(false);
                    employee.setDisabilityDetails("");
                }

                if (request.getParameter("isInjured").equalsIgnoreCase("true")) {
                    employee.setIsInjured(true);
                    employee.setInjureDetails(request.getParameter("injureDetails"));
                } else {
                    employee.setIsInjured(false);
                    employee.setInjureDetails("");
                }
                employee.setHobbies(request.getParameter("hobbies"));
                employee.setExpectedSalary(request.getParameter("expectedSalary").equalsIgnoreCase("NA") ? 0 : Double.valueOf(request.getParameter("expectedSalary")));
//                employee.setWagesPerDay(Double.valueOf(request.getParameter("wagesPerDay")));
                employee.setDoj(LocalDate.parse(request.getParameter("doj")));
                employee.setBankName(request.getParameter("bankName"));
                employee.setBranchName(request.getParameter("branchName"));
                employee.setAccountNo(request.getParameter("accountNo"));
                employee.setIfscCode(request.getParameter("ifscCode"));
                employee.setPfNumber(request.getParameter("pfNumber"));
                employee.setEsiNumber(request.getParameter("esiNumber"));
                employee.setPanNumber(request.getParameter("panNumber"));

                employee.setEmployeeHavePf(Boolean.parseBoolean(request.getParameter("employeeHavePf")));
                if (Boolean.parseBoolean(request.getParameter("employeeHavePf"))) {
//            employee.setEmployerPf(Double.valueOf(request.getParameter("employerPf")));
//                    employee.setEmployeePf(Double.valueOf(request.getParameter("employeePf")));
                    employee.setPfNumber(request.getParameter("pfNumber"));
                    Payhead payhead = utility.getPayheadByKey("pf");
                    if(payhead != null) {
                        EmployeePayhead employeePayhead = new EmployeePayhead();
                        employeePayhead.setPayhead(payhead);
                        employeePayheadList.add(employeePayhead);
                    }
                }

                employee.setEmployeeHaveEsi(Boolean.parseBoolean(request.getParameter("employeeHaveEsi")));
                if (Boolean.parseBoolean(request.getParameter("employeeHaveEsi"))) {
//            employee.setEmployerEsi(Double.valueOf(request.getParameter("employerEsi")));
                    employee.setEsiNumber(request.getParameter("esiNumber"));
//                    employee.setEmployeeEsi(Double.valueOf(request.getParameter("employeeEsi")));
                    Payhead payhead = utility.getPayheadByKey("esi");
                    if(payhead != null) {
                        EmployeePayhead employeePayhead = new EmployeePayhead();
                        employeePayhead.setPayhead(payhead);
                        employeePayheadList.add(employeePayhead);
                    }
                }
                employee.setEmployeeHaveProfTax(Boolean.parseBoolean(request.getParameter("employeeHaveProfTax")));
                if (Boolean.parseBoolean(request.getParameter("employeeHaveProfTax"))) {
                    Payhead payhead = utility.getPayheadByKey("pt");
                    if(payhead != null) {
                        EmployeePayhead employeePayhead = new EmployeePayhead();
                        employeePayhead.setPayhead(payhead);
                        employeePayheadList.add(employeePayhead);
                    }
                }
                employee.setShowSalarySheet(Boolean.parseBoolean(request.getParameter("showSalarySheet")));

                employee.setGender(request.getParameter("gender"));
                employee.setStatus(true);

                employee.setTextPassword("1234");
                String encPassword = passwordEncoder.encode("1234");
                employee.setPassword(encPassword);

                employee.setWagesOptions(request.getParameter("wagesOptions"));
                employee.setEmployeeWagesType(request.getParameter("employeeWagesType"));
                employee.setWeeklyOffDay(Integer.parseInt(request.getParameter("weeklyOffDay")));
                employee.setEffectedDate(LocalDate.parse(request.getParameter("effectiveDate")));
                employee.setExpectedSalary(Double.parseDouble(request.getParameter("expectedSalary")));

                Designation designation = designationRepository.findByIdAndStatus(Long.parseLong(request.getParameter("designationId")), true);
                if (designation != null) {
                    employee.setDesignation(designation);
                }

                if (request.getParameter("shiftId") != null && !request.getParameter("shiftId").equalsIgnoreCase("undefined")) {
                    Shift shift = shiftRepository.findByIdAndStatus(Long.parseLong(request.getParameter("shiftId")), true);
                    if (shift != null) {
                        employee.setShift(shift);
                    }
                }

                if (request.getParameter("companyId") != null) {
                    Company company = companyRepository.findByIdAndStatus(Long.parseLong(request.getParameter("companyId")), true);
                    if (company != null) {
                        employee.setCompany(company);
                    }
                }

                if (request.getParameter("branchId") != null) {
                    Branch branch = branchRepository.findByIdAndStatus(Long.parseLong(request.getParameter("branchId")), true);
                    if (branch != null) {
                        employee.setBranch(branch);
                    }
                }

                if(request.getParameter("departmentId")!=null){
                    Department department=departmentRepository.findByIdAndStatus(Long.parseLong(request.getParameter("departmentId")),true);
                    if(department!=null){
                        employee.setDepartment(department);
                    }
                }

                Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
                employee.setCreatedBy(user.getId());
                employee.setEmployeePayheadList(employeePayheadList);

                Users reportingManager = usersRepository.findByIdAndStatus(Long.parseLong(request.getParameter("reportingManagerId")), true);
                employee.setReportingManager(reportingManager);
                List<EmployeeFamily> employeeFamilyList = new ArrayList<>();
                String jsonToStr = request.getParameter("family");
                JsonArray array = new JsonParser().parse(jsonToStr).getAsJsonArray();
                for (JsonElement jsonElement1 : array) {
                    JsonObject jsonObject = jsonElement1.getAsJsonObject();
                    if (jsonObject.get("fullName").getAsString() != null) {
                        EmployeeFamily employeeFamily = this.getEmployeeFamilyFromJsonObject(jsonObject, user);
                        employeeFamilyList.add(employeeFamily);
                    }
                }

                List<EmployeeEducation> employeeEducationList = new ArrayList<>();
                String jsonToStr1 = request.getParameter("education");
                JsonArray educationArray = new JsonParser().parse(jsonToStr1).getAsJsonArray();
                for (JsonElement jsonElement : educationArray) {
                    JsonObject object = jsonElement.getAsJsonObject();
                    if (object.get("institutionName").getAsString() != null) {
                        EmployeeEducation employeeEducation = this.getEmployeeEducationFromJsonObject(object, user);
                        employeeEducationList.add(employeeEducation);
                    }
                }

                List<EmployeeDocument> employeeDocumentList = new ArrayList<>();
                String jsonToStr2 = request.getParameter("document");
                JsonArray documentArray = new JsonParser().parse(jsonToStr2).getAsJsonArray();
                for (int i = 0; i < documentArray.size(); i++) {
                    JsonObject object = documentArray.get(i).getAsJsonObject();
                    if (object.get("d_documentId") != null) {
                        EmployeeDocument employeeDocument = new EmployeeDocument();
                        Long docObject = object.get("d_documentId").getAsLong();
                        Document document = documentRepository.findByIdAndStatus(docObject, true);
                        employeeDocument.setDocument(document);

                        if (request.getFile("document" + i) != null) {
                            MultipartFile image = request.getFile("document" + i);
                            fileStorageProperties.setUploadDir("./uploads" + File.separator + "emp_documents" + File.separator);
                            String imagePath = fileStorageService.storeFile(image, fileStorageProperties);

                            if (imagePath != null) {
                                employeeDocument.setImagePath("/uploads" + File.separator + "emp_documents" + File.separator + imagePath);
                            } else {
                                responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                                responseObject.setMessage("Failed to upload documents. Please try again!");
                                return responseObject;
                            }
                        } else {
                            responseObject.setMessage("Please upload document");
                            responseObject.setResponseStatus(HttpStatus.NOT_FOUND.value());
                            return responseObject;
                        }

                        employeeDocument.setCreatedBy(user.getId());
                        employeeDocument.setStatus(true);
                        employeeDocumentList.add(employeeDocument);
                    }
                }

                List<EmployeeExperienceDetails> experienceDetailsList = new ArrayList<>();
                String jsonToStr3 = request.getParameter("experience");
                JsonArray experienceArray = new JsonParser().parse(jsonToStr3).getAsJsonArray();
                for (JsonElement jsonElement : experienceArray) {
                    JsonObject object = jsonElement.getAsJsonObject();
                    if (object.get("companyName").getAsString() != null) {
                        EmployeeExperienceDetails employeeExperienceDetails = this.getEmployeeExperienceFromJsonObject(object, user);
                        experienceDetailsList.add(employeeExperienceDetails);
                    }
                }

                List<EmployeeReference> employeeReferenceList = new ArrayList<>();
                String jsonToStr4 = request.getParameter("reference");
                JsonArray jsonArray = new JsonParser().parse(jsonToStr4).getAsJsonArray();
                for (JsonElement jsonElement : jsonArray) {
                    JsonObject object = jsonElement.getAsJsonObject();
                    if (object.get("name").getAsString() != null) {
                        EmployeeReference employeeReference = this.getEmployeeReferenceFromJsonObject(object, user);
                        employeeReferenceList.add(employeeReference);
                    }
                }
                if(employeeFamilyList.size() > 0)
                    employee.setEmployeeFamily(employeeFamilyList);
                if(employeeEducationList.size() > 0)
                    employee.setEmployeeEducation(employeeEducationList);
                if(employeeDocumentList.size() > 0)
                    employee.setEmployeeDocuments(employeeDocumentList);
                if(employeeReferenceList.size() > 0)
                    employee.setEmployeeReferences(employeeReferenceList);
                if(experienceDetailsList.size() > 0)
                    employee.setEmployeeExperienceDetails(experienceDetailsList);

                try {
                    entityManager.persist(employee);
                    Employee employee1 = employeeRepository.save(employee);
                    if(employee1 != null) {

                        PrincipleGroups groups = principleGroupsRepository.findByIdAndStatus(5L, true);
                        Principles principles = groups.getPrinciples();
                        Foundations foundations = principles.getFoundations();
                        BalancingMethod balancingMethod = balancingMethodRepository.findByIdAndStatus(2L, true);
                        LedgerMaster mLedgerMaster = new LedgerMaster();
                        mLedgerMaster.setUniqueCode("SUCR");
                        mLedgerMaster.setOpeningBalType("CR");
                        mLedgerMaster.setAddress("NA");
                        mLedgerMaster.setOpeningBal(0.0);
                        mLedgerMaster.setPincode(0L);
                        mLedgerMaster.setEmail("NA");
                        mLedgerMaster.setMobile(employee1.getMobileNumber());
                        mLedgerMaster.setTaxable(false);
                        mLedgerMaster.setGstin("NA");
                        mLedgerMaster.setStateCode("NA");
                        mLedgerMaster.setPancard("NA");
                        mLedgerMaster.setBankName("NA");
                        mLedgerMaster.setAccountNumber("NA");
                        mLedgerMaster.setIfsc("NA");
                        mLedgerMaster.setBankBranch("NA");
                        mLedgerMaster.setCreatedBy(user.getId());
                        mLedgerMaster.setTaxType("NA");
                        mLedgerMaster.setSlugName("sundry_creditors");
                        mLedgerMaster.setStatus(true);
                        mLedgerMaster.setUnderPrefix("AG#1");
                        mLedgerMaster.setIsDefaultLedger(false);
                        mLedgerMaster.setIsDeleted(true);
                        mLedgerMaster.setPrinciples(principles);
                        mLedgerMaster.setFoundations(foundations);
                        mLedgerMaster.setPrincipleGroups(groups);
                        mLedgerMaster.setBranch(employee1.getBranch());
                        mLedgerMaster.setCompany(employee1.getCompany());
                        mLedgerMaster.setBalancingMethod(balancingMethod);
                        mLedgerMaster.setLedgerName(employee1.getFirstName()+" "+employee1.getMiddleName()+" "+employee1.getLastName());
                        mLedgerMaster.setMailingName(employee1.getFirstName()+" "+employee1.getMiddleName()+" "+employee1.getLastName());
                        mLedgerMaster.setEmployee(employee1);
                        LedgerMaster newLedger = ledgerMasterRepository.save(mLedgerMaster);
                        if(newLedger != null) {
                            responseObject.setMessage("Employee added successfully");
                            responseObject.setResponseStatus(HttpStatus.OK.value());
                        } else {
                            responseObject.setMessage("Error while creating employee ledger");
                            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                        }
                    } else {
                        responseObject.setMessage("Error while saving employee data");
                        responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println(" e " + e.getMessage());
                    responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    responseObject.setMessage("Internal Server Error");
                }
            }
        } catch (Exception e) {
            responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            responseObject.setMessage("Internal Server Error");
            e.printStackTrace();
            System.out.println("Exception:" + e.getMessage());
        }
        return responseObject;
    }

    public Object updateEmployee(MultipartHttpServletRequest request) {
        ResponseMessage responseObject = new ResponseMessage();
        FileStorageProperties fileStorageProperties = new FileStorageProperties();
        try {
            Employee employee = employeeRepository.findById(Long.parseLong(request.getParameter("id"))).get();
            if (employee != null) {
                if(request.getParameterMap().containsKey("firstName"))
                    employee.setFirstName(request.getParameter("firstName"));
                if(request.getParameterMap().containsKey("middleName"))
                    employee.setMiddleName(request.getParameter("middleName"));
                if(request.getParameterMap().containsKey("lastName"))
                    employee.setLastName(request.getParameter("lastName"));
                if(request.getParameterMap().containsKey("fullName"))
                    employee.setFullName(request.getParameter("fullName"));
                else
                    employee.setFullName(request.getParameter("firstName")+" "+request.getParameter("middleName")+" "+request.getParameter("lastName"));
                if(request.getParameterMap().containsKey("fullAddress"))
                    employee.setPermanentAddress(request.getParameter("fullAddress"));
                if(request.getParameterMap().containsKey("mobileNumber"))
                    employee.setMobileNumber(Long.parseLong(request.getParameter("mobileNumber")));
                if(request.getParameterMap().containsKey("dob"))
                    employee.setDob(LocalDate.parse(request.getParameter("dob")));
                if(request.getParameterMap().containsKey("age"))
                    employee.setAge(Integer.parseInt(request.getParameter("age")));
                if(request.getParameterMap().containsKey("religion"))
                    employee.setReligion(request.getParameter("religion"));
                if(request.getParameterMap().containsKey("cast"))
                    employee.setCast(request.getParameter("cast"));
                if(request.getParameterMap().containsKey("reasonToJoin"))
                    employee.setReasonToJoin(request.getParameter("reasonToJoin"));
                if(request.getParameterMap().containsKey("marriageStatus"))
                    employee.setMarriageStatus(request.getParameter("marriageStatus"));
                if(request.getParameterMap().containsKey("emergencyRelation"))
                    employee.setEmergencyRelation(request.getParameter("emergencyRelation"));
                if(request.getParameterMap().containsKey("emergencyContact"))
                    employee.setEmergencyContact(request.getParameter("emergencyContact"));
                if(request.getParameterMap().containsKey("height")) {
                    if (!request.getParameter("height").equalsIgnoreCase("null") && !request.getParameter("height").equalsIgnoreCase("NA"))
                        employee.setHeight(Double.parseDouble(request.getParameter("height")));
                }
                if(request.getParameterMap().containsKey("weight")) {
                    if (!request.getParameter("weight").equalsIgnoreCase("null") && !request.getParameter("weight").equalsIgnoreCase("NA"))
                        employee.setWeight(Double.parseDouble(request.getParameter("weight")));
                }
                if(request.getParameterMap().containsKey("bloodGroup"))
                    employee.setBloodGroup(request.getParameter("bloodGroup"));
                if(request.getParameterMap().containsKey("employeeType"))
                    employee.setEmployeeType(request.getParameter("employeeType"));
                if(request.getParameterMap().containsKey("isExperienceEmployee"))
                    employee.setIsExperienceEmployee(request.getParameter("isExperienceEmployee").equalsIgnoreCase("true"));
                if(request.getParameterMap().containsKey("isDisability")) {
                    if (request.getParameter("isDisability").equalsIgnoreCase("true")) {
                        employee.setIsDisability(true);
                        employee.setDisabilityDetails(request.getParameter("disabilityDetails"));
                    } else {
                        employee.setIsDisability(false);
                        employee.setDisabilityDetails("");
                    }
                }
                if(request.getParameterMap().containsKey("isInjured")) {
                    if (request.getParameter("isInjured").equalsIgnoreCase("true")) {
                        employee.setIsInjured(true);
                        employee.setInjureDetails(request.getParameter("injureDetails"));
                    } else {
                        employee.setIsInjured(false);
                        employee.setInjureDetails("");
                    }
                }
                if(request.getParameterMap().containsKey("wagesOptions"))
                    employee.setWagesOptions(request.getParameter("wagesOptions"));
                if(request.getParameterMap().containsKey("employeeWagesType"))
                    employee.setEmployeeWagesType(request.getParameter("employeeWagesType"));
                if(request.getParameterMap().containsKey("weeklyOffDay"))
                    employee.setWeeklyOffDay(Integer.parseInt(request.getParameter("weeklyOffDay")));
                if(request.getParameterMap().containsKey("hobbies"))
                    employee.setHobbies(request.getParameter("hobbies"));
                employee.setExpectedSalary(request.getParameterMap().containsKey("expectedSalary") ?
                        request.getParameter("expectedSalary").equalsIgnoreCase("NA") ? 0 : Double.valueOf(request.getParameter("expectedSalary"))
                        : 0);
                if (request.getParameterMap().containsKey("wagesPerDay") && !request.getParameter("wagesPerDay").equalsIgnoreCase("null")) {
                    employee.setWagesPerDay(Double.valueOf(request.getParameter("wagesPerDay")));
                }
                if(request.getParameterMap().containsKey("doj"))
                    employee.setDoj(LocalDate.parse(request.getParameter("doj")));
                if(request.getParameterMap().containsKey("bankName"))
                    employee.setBankName(request.getParameter("bankName"));
                if(request.getParameterMap().containsKey("branchName"))
                    employee.setBranchName(request.getParameter("branchName"));
                if(request.getParameterMap().containsKey("accountNo"))
                    employee.setAccountNo(request.getParameter("accountNo"));
                if(request.getParameterMap().containsKey("ifscCode"))
                    employee.setIfscCode(request.getParameter("ifscCode"));
                if(request.getParameterMap().containsKey("pfNumber"))
                    employee.setPfNumber(request.getParameter("pfNumber"));
                if(request.getParameterMap().containsKey("esiNumber"))
                    employee.setEsiNumber(request.getParameter("esiNumber"));
                if(request.getParameterMap().containsKey("panNumber"))
                    employee.setPanNumber(request.getParameter("panNumber"));
                if(request.getParameterMap().containsKey("employeeHavePf")) {
                    if (Boolean.parseBoolean(request.getParameter("employeeHavePf"))) {
                        employee.setEmployeeHavePf(true);
                        employee.setEmployeePf(Double.valueOf(request.getParameter("employeePf")));
                    }
                }
                if(request.getParameterMap().containsKey("employeeHaveEsi")) {
                    employee.setEmployeeHaveEsi(Boolean.parseBoolean(request.getParameter("employeeHaveEsi")));
                    if (Boolean.parseBoolean(request.getParameter("employeeHaveEsi"))) {
                        employee.setEmployeeEsi(Double.valueOf(request.getParameter("employeeEsi")));
                    }
                }
                if(request.getParameterMap().containsKey("employeeHaveProfTax"))
                    employee.setEmployeeHaveProfTax(Boolean.parseBoolean(request.getParameter("employeeHaveProfTax")));
                if(request.getParameterMap().containsKey("showSalarySheet"))
                    employee.setShowSalarySheet(Boolean.parseBoolean(request.getParameter("showSalarySheet")));
                if(request.getParameterMap().containsKey("gender"))
                    employee.setGender(request.getParameter("gender"));
                employee.setStatus(true);

                Designation designation = designationRepository.findByIdAndStatus(Long.parseLong(request.getParameter("designationId")), true);
                if (designation != null) {
                    employee.setDesignation(designation);
                }

                if (!request.getParameter("shiftId").equalsIgnoreCase("") && !request.getParameter("shiftId").equalsIgnoreCase("undefined")) {
                    Shift shift = shiftRepository.findByIdAndStatus(Long.parseLong(request.getParameter("shiftId")), true);
                    if (shift != null) {
                        employee.setShift(shift);
                    }
                } else {
                    employee.setShift(null);
                }

                if (request.getParameter("companyId") != null) {
                    Company company = companyRepository.findByIdAndStatus(Long.parseLong(request.getParameter("companyId")), true);
                    if (company != null) {
                        employee.setCompany(company);
                    }
                }

                if (request.getParameter("branchId") != null) {
                    Branch branch = branchRepository.findByIdAndStatus(Long.parseLong(request.getParameter("branchId")), true);
                    if (branch != null) {
                        employee.setBranch(branch);
                    }
                }

                if (request.getParameter("departmentId") != null) {
                    Department department = departmentRepository.findByIdAndStatus(Long.parseLong(request.getParameter("departmentId")), true);
                    if (department != null) {
                        employee.setDepartment(department);
                    }
                }

                if (request.getParameterMap().containsKey("reportingManagerId") && request.getParameter("reportingManagerId") != null) {
                    Users reportingManager = usersRepository.findByIdAndStatus(Long.parseLong(request.getParameter("reportingManagerId")), true);
                    employee.setReportingManager(reportingManager);
                }

                Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
                employee.setUpdatedBy(user.getId());
                employee.setUpdatedAt(LocalDateTime.now());
                try {
                    List<EmployeeFamily> employeeFamilyList = new ArrayList<>();
                    String jsonToStr = request.getParameter("family");
                    JsonArray jsonArray = new JsonParser().parse(jsonToStr).getAsJsonArray();
                    for (JsonElement jsonElement : jsonArray) {
                        JsonObject object = jsonElement.getAsJsonObject();

                        if (object.has("id")) {
                            System.out.println("Old family " + object.get("id").getAsLong());
                            EmployeeFamily employeeFamily = employeeFamilyRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
                            employee.getEmployeeFamily().remove(employeeFamily);
                            employeeFamilyRepository.deleteFamilyFromEmployee(object.get("id").getAsLong());
                            System.out.println("Removed family " + object.get("id").getAsLong());
                        }

                        if (object.has("fullName") && object.get("fullName").getAsString() != null) {
                            EmployeeFamily employeeFamily = this.getEmployeeFamilyFromJsonObject(object, user);
                            employeeFamilyList.add(employeeFamily);
                        }
                    }

                    List<EmployeeEducation> employeeEducationList = new ArrayList<>();
                    String jsonToStr1 = request.getParameter("education");
                    JsonArray array1 = new JsonParser().parse(jsonToStr1).getAsJsonArray();
                    for (JsonElement jsonElement : array1) {
                        JsonObject object = jsonElement.getAsJsonObject();
                        if (object.has("id")) {
                            System.out.println("Old education " + object.get("id").getAsLong());
                            EmployeeEducation employeeEducation = employeeEducationRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
                            employee.getEmployeeEducation().remove(employeeEducation);
                            employeeEducationRepository.deleteEducationFromEmployee(object.get("id").getAsLong());
                            System.out.println("Removed education " + object.get("id").getAsLong());
                        }
                        if (object.has("institutionName") && object.get("institutionName").getAsString() != null) {
                            EmployeeEducation employeeEducation = this.getEmployeeEducationFromJsonObject(object, user);
                            employeeEducationList.add(employeeEducation);
                        }
                    }

                    String oldDocRemove = request.getParameter("oldDocRemoveList");
                    JsonArray oldDocRemoveArray = new JsonParser().parse(oldDocRemove).getAsJsonArray();
                    if (oldDocRemoveArray.size() > 0) {
                        for (int i = 0; i < oldDocRemoveArray.size(); i++) {
                            JsonObject object = oldDocRemoveArray.get(i).getAsJsonObject();
                            EmployeeDocument employeeDocument = employeeDocumentRepository.findByIdAndStatus(object.get("empDocumentId").getAsLong(), true);
                            if (employeeDocument != null) {
                                if (employeeDocument.getImagePath() != null) {
                                    File oldFile = new File("." + employeeDocument.getImagePath());

                                    if (oldFile.exists()) {
                                        System.out.println("Document Deleted");
                                        //remove file from local directory
                                        if (!oldFile.delete()) {
                                            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                                            responseObject.setMessage("Failed to delete old documents. Please try again!");
                                            return responseObject;
                                        } else {
                                            employee.getEmployeeDocuments().remove(employeeDocument);
                                            employeeDocumentRepository.deleteDocumentFromEmployee(employeeDocument.getId());
                                            System.out.println("Document Deleted" + employeeDocument.getId());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    List<EmployeeDocument> employeeDocumentList = new ArrayList<>();
                    if(request.getParameterMap().containsKey("document")) {
                        String jsonToStr2 = request.getParameter("document");
                        JsonArray array2 = new JsonParser().parse(jsonToStr2).getAsJsonArray();
                        for (int i = 0; i < array2.size(); i++) {
                            JsonObject object = array2.get(i).getAsJsonObject();

                            if (object.has("id")) {
                                System.out.println("Old document " + object.get("id").getAsLong());
                                EmployeeDocument employeeDocument = employeeDocumentRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
                                employeeDocumentList.add(employeeDocument);
                            } else {
                                if (object.get("d_documentId") != null) {
                                    EmployeeDocument employeeDocument = new EmployeeDocument();
                                    JsonObject docObject = object.get("d_documentId").getAsJsonObject();
                                    Document document = documentRepository.findByIdAndStatus(Long.parseLong(docObject.get("value").getAsString()), true);
                                    employeeDocument.setDocument(document);

                                    if (request.getFile("document" + i) != null) {
                                        MultipartFile image = request.getFile("document" + i);
                                        fileStorageProperties.setUploadDir("./uploads" + File.separator + "emp_documents" + File.separator);
                                        String imagePath = fileStorageService.storeFile(image, fileStorageProperties);

                                        if (imagePath != null) {
                                            employeeDocument.setImagePath("/uploads" + File.separator + "emp_documents" + File.separator + imagePath);
                                        } else {
                                            responseObject.setMessage("Failed to upload documents. Please try again!");
                                            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                                            return responseObject;
                                        }
                                    }
                                    employeeDocument.setCreatedBy(user.getId());
                                    employeeDocument.setStatus(true);
                                    employeeDocumentList.add(employeeDocument);
                                }
                            }
                        }
                    }

//                    String jsonToStrOldDocs = request.getParameter("oldDocumentList");
//                    JsonArray arrayOldDocs = new JsonParser().parse(jsonToStrOldDocs).getAsJsonArray();
//                    for (JsonElement jsonElement : arrayOldDocs) {
//                        JsonObject object = jsonElement.getAsJsonObject();
//                        if (object.has("id")) {
//                            System.out.println("Old document " + object.get("id").getAsLong());
//                            EmployeeDocument employeeDocument = employeeDocumentRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
//                            employeeDocumentList.add(employeeDocument);
//                        }
//                    }

                    List<EmployeeExperienceDetails> experienceDetailsList = new ArrayList<>();
                    String jsonToStr3 = request.getParameter("experience");
                    JsonArray array3 = new JsonParser().parse(jsonToStr3).getAsJsonArray();
                    for (JsonElement jsonElement : array3) {
                        JsonObject object = jsonElement.getAsJsonObject();
                        if (object.has("id")) {
                            System.out.println("Old experience " + object.get("id").getAsLong());
                            EmployeeExperienceDetails employeeExperienceDetails = employeeExperienceRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
                            employee.getEmployeeExperienceDetails().remove(employeeExperienceDetails);
                            employeeExperienceRepository.deleteExperienceFromEmployee(object.get("id").getAsLong());
                            System.out.println("Removed experience " + object.get("id").getAsLong());
                        }
                        if (object.has("companyName") && object.get("companyName").getAsString() != null) {
                            EmployeeExperienceDetails employeeExperienceDetails = this.getEmployeeExperienceFromJsonObject(object, user);
                            experienceDetailsList.add(employeeExperienceDetails);
                        }
                    }

                    List<EmployeeReference> employeeReferenceList = new ArrayList<>();
                    String jsonToStr4 = request.getParameter("reference");
                    JsonArray array4 = new JsonParser().parse(jsonToStr4).getAsJsonArray();
                    for (JsonElement jsonElement : array4) {
                        JsonObject object = jsonElement.getAsJsonObject();
                        if (object.has("id")) {
                            System.out.println("Old reference " + object.get("id").getAsLong());
                            EmployeeReference employeeReference = employeeReferenceRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
                            employee.getEmployeeReferences().remove(employeeReference);
                            employeeReferenceRepository.deleteReferenceFromEmployee(object.get("id").getAsLong());
                            System.out.println("Removed reference " + object.get("id").getAsLong());
                        }
                        if (object.has("name") && object.get("name").getAsString() != null) {
                            EmployeeReference employeeReference = this.getEmployeeReferenceFromJsonObject(object, user);
                            employeeReferenceList.add(employeeReference);
                        }
                    }

//                    String oldSalRemove = request.getParameter("oldsalremoveList");
//                    JsonArray oldSalRemoveArray = new JsonParser().parse(oldSalRemove).getAsJsonArray();
//                    if (oldSalRemoveArray.size() > 0) {
//                        for (int i = 0; i < oldSalRemoveArray.size(); i++) {
//                            JsonObject object = oldSalRemoveArray.get(i).getAsJsonObject();
//                            EmployeeSalary employeeSalary = employeeSalaryRepository.findByIdAndStatus(object.get("empSalId").getAsLong(), true);
//                            if (employeeSalary != null) {
//                                employee.getEmployeeSalaries().remove(employeeSalary);
//                                employeeSalaryRepository.deleteSalaryFromEmployee(employeeSalary.getId());
//                                System.out.println("Salary Deleted" + employeeSalary.getId());
//                            }
//                        }
//                    }

//                    List<EmployeeSalary> employeeSalaryList = new ArrayList<>();
//                    String jsonToEmpSalary = request.getParameter("salaryList");
//                    JsonArray array5 = new JsonParser().parse(jsonToEmpSalary).getAsJsonArray();
//                    for (JsonElement jsonElement : array5) {
//                        JsonObject object = jsonElement.getAsJsonObject();
//                        if (object.has("effectiveDate") && object.get("effectiveDate").getAsString() != null) {
//                            EmployeeSalary employeeSalary = this.getEmployeeSalaryFromJsonObject(object, user, employee);
//                            employeeSalaryList.add(employeeSalary);
//                        }
//                    }
                    try {
                        employee.setEmployeeFamily(employeeFamilyList);
                        employee.setEmployeeEducation(employeeEducationList);
                        if (employeeDocumentList.size() > 0) {
                            employee.setEmployeeDocuments(employeeDocumentList);
                        }
//                        if (employeeSalaryList.size() > 0) {
//                            employee.setEmployeeSalaries(employeeSalaryList);
//                        }
                        employee.setEmployeeReferences(employeeReferenceList);
                        employee.setEmployeeExperienceDetails(experienceDetailsList);

//                        entityManager.persist(employee);
                        Employee employee1 = employeeRepository.save(employee);
                        if(employee1 != null) {
                            responseObject.setMessage("Employee updated successfully");
                            responseObject.setResponseStatus(HttpStatus.OK.value());
                        } else {
                            responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                            responseObject.setMessage("Internal Server Error");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Exception " + e.getMessage());
                        responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                        responseObject.setMessage("Internal Server Error");
                    }

                } catch (Exception e) {
                    responseObject.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    responseObject.setMessage("Internal Server Error");
                    e.printStackTrace();
                    System.out.println("Exception:" + e.getMessage());
                }
            } else {
                responseObject.setResponseStatus(HttpStatus.NOT_FOUND.value());
                responseObject.setMessage("Data not found");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseObject.setMessage("Failed to update employee");
            responseObject.setResponseStatus(HttpStatus.BAD_REQUEST.value());
        }
        return responseObject;
    }

    private EmployeeFamily getEmployeeFamilyFromJsonObject(JsonObject object, Users user) {
        EmployeeFamily employeeFamily = new EmployeeFamily();
        employeeFamily.setFullName(object.get("fullName").getAsString());
        employeeFamily.setDob(object.get("dob").getAsString());
        employeeFamily.setRelation(object.get("relation").getAsString());
        employeeFamily.setEducation(object.get("education").getAsString());
        employeeFamily.setCreatedBy(user.getId());
        employeeFamily.setStatus(true);
        return employeeFamily;
    }

    private EmployeeEducation getEmployeeEducationFromJsonObject(JsonObject object, Users user) {
        EmployeeEducation employeeEducation = new EmployeeEducation();
        employeeEducation.setInstitutionName(object.get("institutionName").getAsString());
        employeeEducation.setQualification(object.get("qualification").getAsString());
        employeeEducation.setUniversity(object.get("university").getAsString());
        employeeEducation.setYear(object.get("year").getAsString());
        employeeEducation.setGrade(object.get("grade").getAsString());
        employeeEducation.setPercentage(object.get("percentage").getAsString());
        employeeEducation.setCreatedBy(user.getId());
        employeeEducation.setStatus(true);
        return employeeEducation;
    }
    private EmployeeExperienceDetails getEmployeeExperienceFromJsonObject(JsonObject object, Users user) {
        EmployeeExperienceDetails employeeExperienceDetails = new EmployeeExperienceDetails();
        employeeExperienceDetails.setCompanyName(object.get("companyName").getAsString());
        employeeExperienceDetails.setFromMonthYear(object.get("fromMonthYear").getAsString());
        employeeExperienceDetails.setToMonthYear(object.get("toMonthYear").getAsString());
        employeeExperienceDetails.setDesignationName(object.get("designationName").getAsString());
        employeeExperienceDetails.setLastDrawnSalary(object.get("lastDrawnSalary").getAsString());
        employeeExperienceDetails.setReasonToResign(object.get("reasonToResign").getAsString());
        employeeExperienceDetails.setCreatedBy(user.getId());
        employeeExperienceDetails.setStatus(true);
        return employeeExperienceDetails;
    }

    private EmployeeReference getEmployeeReferenceFromJsonObject(JsonObject object, Users user) {
        EmployeeReference employeeReference = new EmployeeReference();
        employeeReference.setName(object.get("name").getAsString());
        employeeReference.setAddress(object.get("address").getAsString());
        employeeReference.setBusiness(object.get("business").getAsString());
        employeeReference.setMobileNumber(object.get("mobileNumber").getAsString());
//        employeeReference.setKnownFromWhen(object.get("knownFromWhen").getAsString());
        employeeReference.setCreatedBy(user.getId());
        employeeReference.setStatus(true);
        return employeeReference;
    }

    public Object findEmp(Long mobileNumber) throws UsernameNotFoundException {
        Employee employee = employeeRepository.findByMobileNumber(mobileNumber);
        if (employee == null) {
            throw new UsernameNotFoundException("User not found with username: " + mobileNumber);
        }
        return employee;
    }

    public Object findEmployee(Map<String, String> request) {
        ResponseMessage responseMessage = new ResponseMessage();
        try {
            Employee employee = employeeRepository.findById(Long.parseLong(request.get("id"))).get();
            EmployeeDTO employeeDTO = new EmployeeDTO();
            if (employee != null) {
                employeeDTO = convertEmployeeToEmployeeDTO(employee);
                responseMessage.setResponse(employeeDTO);
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } else {
                responseMessage.setMessage("Data not found");
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            responseMessage.setMessage("Failed to load data");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }
    private EmployeeDTO convertEmployeeToEmployeeDTO(Employee employee) {
        EmployeeDTO employeeDTO = new EmployeeDTO();
        employeeDTO.setId(employee.getId());
        employeeDTO.setFirstName(employee.getFirstName());
        employeeDTO.setMiddleName(employee.getMiddleName());
        employeeDTO.setLastName(employee.getLastName());
        employeeDTO.setFullName(utility.getEmployeeName(employee));
        employeeDTO.setReportingManager(employee.getReportingManager() != null ? employee.getReportingManager().getId().toString() : "");

        if (employee.getDob() != null) employeeDTO.setDob(employee.getDob().toString());
        employeeDTO.setGender(employee.getGender());
        employeeDTO.setMobileNumber(employee.getMobileNumber());
        employeeDTO.setEmployeeType(employee.getEmployeeType());
        employeeDTO.setCreatedAt(String.valueOf(employee.getCreatedAt()));
        employeeDTO.setStatus(employee.getStatus());
        employeeDTO.setDesignation(employee.getDesignation());
        employeeDTO.setShift(employee.getShift() != null ? employee.getShift() : null);
        employeeDTO.setCompany(employee.getCompany() != null ? employee.getCompany() : null);
        employeeDTO.setBranch(employee.getBranch() != null ? employee.getBranch() : null);
        employeeDTO.setDepartment(employee.getDepartment() != null ? employee.getDepartment() : null);
        employeeDTO.setWagesOptions(employee.getWagesOptions());
        employeeDTO.setEmployeeWagesType(employee.getEmployeeWagesType());
        employeeDTO.setWeeklyOffDay(employee.getWeeklyOffDay());
        employeeDTO.setAddress(employee.getPermanentAddress());
        employeeDTO.setCast(employee.getCast());
        employeeDTO.setReasonToJoin(employee.getReasonToJoin());
        employeeDTO.setAge(employee.getAge());
        employeeDTO.setReligion(employee.getReligion());
        employeeDTO.setMarriageStatus(employee.getMarriageStatus());
        employeeDTO.setHeight(employee.getHeight());
        employeeDTO.setWeight(employee.getWeight());
        employeeDTO.setBloodGroup(employee.getBloodGroup());
        employeeDTO.setIsDisability(employee.getIsDisability());
        employeeDTO.setDisabilityDetails(employee.getDisabilityDetails());
        employeeDTO.setIsInjured(employee.getIsInjured());
        employeeDTO.setInjureDetails(employee.getInjureDetails());
//
//        Double empPerDaySal = utility.getEmployeeWages(employee.getId());
//        double perDaySal = 0;
//        if (empPerDaySal != null) {
//            perDaySal = empPerDaySal;
//        }
        employeeDTO.setWagesPerDay(employee.getWagesPerDay());
        employeeDTO.setEmployeeHavePf(employee.getEmployeeHavePf());
        employeeDTO.setEmployerPf(employee.getEmployerPf());
        employeeDTO.setEmployeePf(employee.getEmployeePf());
        employeeDTO.setEmployeeHaveEsi(employee.getEmployeeHaveEsi());
        employeeDTO.setEmployerEsi(employee.getEmployerEsi());
        employeeDTO.setEmployeeEsi(employee.getEmployeeEsi());
        employeeDTO.setEmployeeHaveProfTax(employee.getEmployeeHaveProfTax());
        employeeDTO.setShowSalarySheet(employee.getShowSalarySheet());

        employeeDTO.setEmployeeFamily(employee.getEmployeeFamily());
        employeeDTO.setEmployeeEducation(employee.getEmployeeEducation());
        employeeDTO.setEmployeeExperienceDetails(employee.getEmployeeExperienceDetails());
        employeeDTO.setEmployeeDocuments(employee.getEmployeeDocuments());
        employeeDTO.setEmployeeReferences(employee.getEmployeeReferences());
        employeeDTO.setIsExperienceEmployee(employee.getIsExperienceEmployee());
        employeeDTO.setHobbies(employee.getHobbies());
        employeeDTO.setExpectedSalary(employee.getExpectedSalary());
        if (employee.getDoj() != null) employeeDTO.setDoj(employee.getDoj().toString());
        employeeDTO.setBankName(employee.getBankName());
        employeeDTO.setBranchName(employee.getBranchName());
        employeeDTO.setDepartmentName(employee.getDepartmentName());
        employeeDTO.setAccountNo(employee.getAccountNo());
        employeeDTO.setIfscCode(employee.getIfscCode());
        employeeDTO.setPfNumber(employee.getPfNumber());
        employeeDTO.setEsiNumber(employee.getEsiNumber());
        employeeDTO.setPanNumber(employee.getPanNumber());
        employeeDTO.setCorrespondenceAddress(employee.getCorrespondenceAddress());
        employeeDTO.setPermanentAddress(employee.getPermanentAddress());
        employeeDTO.setPresentAddress(employee.getPresentAddress());
        employeeDTO.setEmergencyRelation(employee.getEmergencyRelation());
        employeeDTO.setEmergencyContact(employee.getEmergencyContact());
        return employeeDTO;
    }
    public Object changeEmployeeStatus(Map<String, String> requestParam, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Employee employee = employeeRepository.findById(Long.parseLong(requestParam.get("id"))).get();
        if (employee != null) {
            String status = "";
            if (Boolean.parseBoolean(requestParam.get("status"))) {
                status = "activated";
            } else {
                status = "de-activated";
            }
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            employee.setStatus(Boolean.parseBoolean(requestParam.get("status")));
            employee.setUpdatedBy(user.getId());
            employee.setUpdatedAt(LocalDateTime.now());
            try {
                employeeRepository.save(employee);
                responseMessage.setMessage("Employee " + status + " successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                responseMessage.setMessage("Failed to change status");
            }
        } else {
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            responseMessage.setMessage("Data not found");
        }
        return responseMessage;
    }
    public Employee findUserByMobile(String username, String password) {
        Employee employee = employeeRepository.findByMobileNumber(Long.parseLong(username));
        if (passwordEncoder.matches(password, employee.getPassword())) {
            return employee;
        }
        return null;
    }

    public Object forgetPassword(Map<String, String> request, HttpServletRequest httpServletRequest) {
        Employee emp = jwtTokenUtil.getEmployeeDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        ResponseMessage responseMessage = new ResponseMessage();
        String mobileNumber = request.get("mobile_number");
        Employee employee = employeeRepository.findByCompanyIdAndMobileNumber(emp.getCompany().getId(), Long.parseLong(mobileNumber));
        if (employee != null) {
            employee.setTextPassword(request.get("password"));
            String encPassword = passwordEncoder.encode(request.get("password"));
            employee.setPassword(encPassword);
            try {
                employeeRepository.save(employee);
                responseMessage.setMessage("Password changed successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed change password");
                responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } else {
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
            responseMessage.setMessage("User not exist with mobile number, Try again.");
        }
        return responseMessage;
    }

    public Object checkMobileNumberExists(Map<String, String> request) {
        ResponseMessage responseMessage = new ResponseMessage();
        if(request.containsKey("isOwner")){
            if(Boolean.parseBoolean(request.get("isOwner"))){
                String username = request.get("username");
                Users user = usersRepository.findByUsernameAndStatus(username, true);
                if(user != null){
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                    responseMessage.setMessage("Entered username is valid");
                } else {
                    responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
                    responseMessage.setMessage("User Not Found");
                }
            }
        } else {
            String mobileNumber = request.get("mobile_number");
            Employee employee = employeeRepository.findByMobileNumberAndStatus(Long.parseLong(mobileNumber), true);
            if (employee != null) {
                responseMessage.setResponseStatus(HttpStatus.OK.value());
                responseMessage.setMessage("Entered mobile number is valid");
            } else {
                responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
                responseMessage.setMessage("Please Enter Registered Mobile number");
            }
        }
        return responseMessage;
    }
    public JsonObject listOfEmployee(HttpServletRequest httpServletRequest) {
        Users users = jwtTokenUtil.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<Employee> employeeList = null;
        try {
            if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("CADMIN")) {
                employeeList = employeeRepository.findByCompanyIdAndStatus(users.getCompany().getId(), true);
            } else if(users.getUserRole() != null && users.getUserRole().equalsIgnoreCase("BADMIN")) {
                employeeList = employeeRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(), users.getBranch().getId(), true);
            }
            if(employeeList != null) {
                for (Employee employee : employeeList) {
                    JsonObject object = new JsonObject();
                    object.addProperty("id", employee.getId());
                    object.addProperty("firstName", employee.getFirstName());
                    object.addProperty("middleName", employee.getMiddleName());
                    object.addProperty("lastName", employee.getLastName());
                    object.addProperty("mobileNumber", employee.getMobileNumber());
                    object.addProperty("dob", employee.getDob().toString());
                    Designation designation = designationRepository.findByIdAndStatus(employee.getDesignation().getId(), true);
                    object.addProperty("designationName", designation.getDesignationName());
                    Shift shift = shiftRepository.findByIdAndStatus(employee.getShift().getId(), true);
                    object.addProperty("ShiftName", shift.getShiftName());
                    Level level = levelRepository.findByIdAndStatus(designation.getLevel().getId(), true);
                    object.addProperty("designationLevel", level.getLevelName());
                    object.addProperty("employeeName", utility.getEmployeeName(employee));
                    object.addProperty("reportingManager", employee.getReportingManager() != null ? employee.getReportingManager().getFullName() : "");
                    jsonArray.add(object);
                }
                response.add("response", jsonArray);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "Data not found");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }
    public JsonObject employeeList(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        Employee emp = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
        try {
            List<Employee> employeeList = employeeRepository.findByCompanyIdOrderByFirstName(emp.getCompany().getId());

            for (Employee employee : employeeList) {
                JsonObject object = new JsonObject();
                object.addProperty("id", employee.getId());
                object.addProperty("employeeName", utility.getEmployeeName(employee));
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

    public Object createEmpLedgers(HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        JsonArray jsonArray = new JsonArray();
        JsonObject response = new JsonObject();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            try {
                List<Employee> employeeList = employeeRepository.findByCompanyIdAndStatus(users.getCompany().getId(), true);
                System.out.println("employeeList>>"+employeeList.size());
                for (Employee employee : employeeList) {
                    PrincipleGroups groups = principleGroupsRepository.findByIdAndStatus(5L, true);
                    Principles principles = groups.getPrinciples();
                    Foundations foundations = principles.getFoundations();
                    BalancingMethod balancingMethod = balancingMethodRepository.findByIdAndStatus(2L, true);
                    LedgerMaster mLedgerMaster = new LedgerMaster();
                    mLedgerMaster.setUniqueCode("SUCR");
                    mLedgerMaster.setOpeningBalType("CR");
                    mLedgerMaster.setAddress("NA");
                    mLedgerMaster.setOpeningBal(0.0);
                    mLedgerMaster.setPincode(0L);
                    mLedgerMaster.setEmail("NA");
                    mLedgerMaster.setMobile(employee.getMobileNumber());
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
                    mLedgerMaster.setSlugName("sundry_creditors");
                    mLedgerMaster.setStatus(true);
                    mLedgerMaster.setUnderPrefix("AG#1");
                    mLedgerMaster.setIsDefaultLedger(false);
                    mLedgerMaster.setIsDeleted(true);
                    mLedgerMaster.setPrinciples(principles);
                    mLedgerMaster.setFoundations(foundations);
                    mLedgerMaster.setPrincipleGroups(groups);
                    mLedgerMaster.setBranch(employee.getBranch());
                    mLedgerMaster.setCompany(employee.getCompany());
                    mLedgerMaster.setBalancingMethod(balancingMethod);
                    mLedgerMaster.setLedgerName(employee.getFirstName()+" "+employee.getMiddleName()+" "+employee.getLastName());
                    mLedgerMaster.setMailingName(employee.getFirstName()+" "+employee.getMiddleName()+" "+employee.getLastName());
                    mLedgerMaster.setEmployee(employee);
                    LedgerMaster newLedger = ledgerMasterRepository.save(mLedgerMaster);
                }
                responseMessage.setMessage("Employee ledgers created successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to create emp ledgers");
                responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }

    public Object createSingleEmpLedger(HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            try {
                Employee employee = employeeRepository.findByIdAndStatus(Long.parseLong(request.getParameter("emp_id")),true);
                PrincipleGroups groups = principleGroupsRepository.findByIdAndStatus(5L, true);
                Principles principles = groups.getPrinciples();
                Foundations foundations = principles.getFoundations();
                BalancingMethod balancingMethod = balancingMethodRepository.findByIdAndStatus(2L, true);
                LedgerMaster mLedgerMaster = new LedgerMaster();
                mLedgerMaster.setUniqueCode("SUCR");
                mLedgerMaster.setOpeningBalType("CR");
                mLedgerMaster.setAddress("NA");
                mLedgerMaster.setOpeningBal(0.0);
                mLedgerMaster.setPincode(0L);
                mLedgerMaster.setEmail("NA");
                mLedgerMaster.setMobile(employee.getMobileNumber());
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
                mLedgerMaster.setSlugName("sundry_creditors");
                mLedgerMaster.setStatus(true);
                mLedgerMaster.setUnderPrefix("AG#1");
                mLedgerMaster.setIsDefaultLedger(false);
                mLedgerMaster.setIsDeleted(true);
                mLedgerMaster.setPrinciples(principles);
                mLedgerMaster.setFoundations(foundations);
                mLedgerMaster.setPrincipleGroups(groups);
                mLedgerMaster.setBranch(employee.getBranch());
                mLedgerMaster.setCompany(employee.getCompany());
                mLedgerMaster.setBalancingMethod(balancingMethod);
                mLedgerMaster.setLedgerName(employee.getFirstName()+" "+employee.getMiddleName()+" "+employee.getLastName());
                mLedgerMaster.setMailingName(employee.getFirstName()+" "+employee.getMiddleName()+" "+employee.getLastName());
                mLedgerMaster.setEmployee(employee);
                LedgerMaster newLedger = ledgerMasterRepository.save(mLedgerMaster);
                responseMessage.setMessage("Employee ledger created successfully");
                responseMessage.setResponseStatus(HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Exception " + e.getMessage());
                responseMessage.setMessage("Failed to create emp ledgers");
                responseMessage.setResponseStatus(HttpStatus.BAD_REQUEST.value());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            responseMessage.setMessage("Data not found");
            responseMessage.setResponseStatus(HttpStatus.NOT_FOUND.value());
        }
        return responseMessage;
    }
    public Object getStaffList(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<Employee> employeeList = null;
        try {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            if(user != null && (user.getIsAdmin() || user.getIsSuperAdmin())){
                employeeList = employeeRepository.findByStatus(true);
            } else {
                employeeList = employeeRepository.findByCompanyIdAndStatus(user.getCompany().getId(), true);
            }
            if(employeeList != null) {
                for (Employee employee : employeeList) {
                    JsonObject object = new JsonObject();
                    object.addProperty("id", employee.getId());
                    object.addProperty("employeeName", utility.getEmployeeName(employee));
                    object.addProperty("designation", employee.getDesignation().getDesignationName());
                    object.addProperty("employeeName", utility.getEmployeeName(employee));
                    object.addProperty("profilePicture", "");
                    object.addProperty("branch", employee.getBranch().getBranchName());
                    jsonArray.add(object);
                }
                response.add("response", jsonArray);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "Employee Data not found");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }
    public Object getEmployeePersonalInfo(Map<String, String> jsonRequest, HttpServletRequest request) {
        JsonObject response = new JsonObject();
        Employee employee = null;
        try {
            if(jsonRequest.containsKey("isOwner") && Boolean.parseBoolean(jsonRequest.get("isOwner"))) {
                Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
                Long employeeId = Long.parseLong(jsonRequest.get("employee_id"));
                if (user != null && (user.getIsAdmin() || user.getIsSuperAdmin())) {
                    employee = employeeRepository.findByIdAndStatus(employeeId, true);
                } else {
                    employee = employeeRepository.findByIdAndCompanyIdAndStatus(employeeId, user.getCompany().getId(), true);
                }
            } else {
                employee = jwtTokenUtil.getEmployeeDataFromToken(request.getHeader("Authorization").substring(7));
            }
            if(employee != null) {
                JsonObject object = new JsonObject();
                object.addProperty("id", employee.getId());
                object.addProperty("employeeName", utility.getEmployeeName(employee));
                object.addProperty("designation", employee.getDesignation().getDesignationName());
                object.addProperty("profilePicture", "");
                object.addProperty("dob", employee.getDob().toString());
                object.addProperty("joiningDate", employee.getDoj().toString());
                object.addProperty("bloodGroup", employee.getBloodGroup());
                object.addProperty("contact", employee.getMobileNumber());
                object.addProperty("address", employee.getPresentAddress());
                object.addProperty("workEmailId", "NA");
                object.addProperty("personalEmailId", "NA");
                object.addProperty("emergencyContact", "NA");
                response.add("response", object);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "Failed to load data");
                response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object deleteEmployee(Map<String, String> jsonRequest, HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        try {
            Users users = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            Employee employee = employeeRepository.findByIdAndStatus(Long.parseLong(jsonRequest.get("id")),
                    true);
            if (employee != null) {
                employee.setStatus(false);
                employee.setUpdatedBy(users.getId());
                employee.setUpdatedAt(LocalDateTime.now());
                try {
                    employeeRepository.save(employee);
                    responseMessage.setResponseStatus(HttpStatus.OK.value());
                    responseMessage.setMessage("Employee deleted successfully");
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
            responseMessage.setMessage("Failed to delete Employee");
            responseMessage.setResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return responseMessage;
    }

    public Object getTeamLeaders(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<Employee> employeeList = null;
        try {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            if(user != null && (user.getIsAdmin() || user.getIsSuperAdmin())){
                employeeList = employeeRepository.findByStatus(true);
            } else {
                employeeList = employeeRepository.findByCompanyIdAndStatus(user.getCompany().getId(), true);
            }
            if(employeeList != null) {
                for (Employee employee : employeeList) {
                    if(employee.getDesignation().getLevel().getLevelName().toLowerCase().equalsIgnoreCase("l2")) {
                        JsonObject object = new JsonObject();
                        JsonObject designationObject = new JsonObject();
                        object.addProperty("id", employee.getId());
                        object.addProperty("teamLeadName", utility.getEmployeeName(employee));
                        object.addProperty("isActive", employee.getStatus());
                        object.addProperty("name", employee.getDesignation().getDesignationName());
                        designationObject.addProperty("name",employee.getDesignation().getDesignationName());
                        designationObject.addProperty("level",employee.getDesignation().getLevel().getLevelName());
                        designationObject.addProperty("id",employee.getDesignation().getId());
                        object.add("designation", designationObject);
                        jsonArray.add(object);
                    }
                }
                response.add("response", jsonArray);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "Employee Data not found");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }
    public Object getEmployees(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray jsonArray = new JsonArray();
        List<Employee> employeeList = null;
        try {
            Users user = jwtTokenUtil.getUserDataFromToken(request.getHeader("Authorization").substring(7));
            if(user != null && (user.getIsAdmin() || user.getIsSuperAdmin())){
                employeeList = employeeRepository.findByStatus(true);
            } else {
                employeeList = employeeRepository.findByCompanyIdAndStatus(user.getCompany().getId(), true);
            }
            if(employeeList != null) {
                for (Employee employee : employeeList) {
                    if(employee.getDesignation().getLevel().getLevelName().toLowerCase().equalsIgnoreCase("l1") || employee.getDesignation().getLevel().getLevelName().toLowerCase().equalsIgnoreCase("l2")) {
                        JsonObject object = new JsonObject();
                        JsonObject designationObject = new JsonObject();
                        object.addProperty("id", employee.getId());
                        object.addProperty("employeeName", utility.getEmployeeName(employee));
                        object.addProperty("isActive", employee.getStatus());
                        object.addProperty("name", employee.getDesignation().getDesignationName());
                        designationObject.addProperty("name",employee.getDesignation().getDesignationName());
                        designationObject.addProperty("level",employee.getDesignation().getLevel().getLevelName());
                        designationObject.addProperty("id",employee.getDesignation().getId());
                        object.add("designation", designationObject);
                        jsonArray.add(object);
                    }
                }
                response.add("response", jsonArray);
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                response.addProperty("message", "Employee Data not found");
                response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
            }
        } catch (Exception e) {
            response.addProperty("message", "Failed to load data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }
}
