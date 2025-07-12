package com.opethic.hrms.HRMSNew.services.master;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.common.GenerateFiscalYear;
import com.opethic.hrms.HRMSNew.common.GenerateSlugs;
import com.opethic.hrms.HRMSNew.dto.ClientDetails;
import com.opethic.hrms.HRMSNew.dto.ClientsListDTO;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerBalanceSummary;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionDetails;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.*;
import com.opethic.hrms.HRMSNew.repositories.master.*;
import com.opethic.hrms.HRMSNew.response.ResponseMessage;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;
import java.text.DecimalFormat;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class LedgerMasterService {

    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private LedgerMasterRepository repository;
    @Autowired
    JwtTokenUtil jwtRequestFilter;
    @Autowired
    PrincipleRepository principleRepository;
    @Autowired
    PrincipleGroupsRepository principleGroupsRepository;
    @Autowired
    BalancingMethodRepository balancingMethodRepository;
    @Autowired
    private StateRepository stateRepository;
    @Autowired
    private CountryRepository countryRepository;
    @Autowired
    private LedgerMasterRepository ledgerRepository;
    @Autowired
    private LedgerBalanceSummaryRepository balanceSummaryRepository;
    @Autowired
    private LedgerTransactionDetailsRepository transactionDetailsRepository;
    @Autowired
    private LedgerGstDetailsRepository ledgerGstDetailsRepository;
    @Autowired
    private LedgerShippingDetailsRepository ledgerShippingDetailsRepository;
    @Autowired
    private LedgerDeptDetailsRepository ledgerDeptDetailsRepository;
    @Autowired
    private LedgerBillingDetailsRepository ledgerBillingDetailsRepository;
    @Autowired
    private SalesmanMasterRepository salesmanMasterRepository;
    @Autowired
    private GenerateSlugs generateSlugs;
    /* @Autowired
     private PaymentTransactionDetailsRepository paymentTransactionDetailsRepo;
     @Autowired
     private TransactionTypeMasterDetailsRepository tranxDetailsRepository;*/
    @Autowired
    private GenerateFiscalYear generateFiscalYear;
    @Autowired
    private AssociateGroupsRepository associateGroupsRepository;
    @Autowired
    private GstTypeMasterRepository gstMasterRepository;
    @Autowired
    private LedgerBankDetailsRepository ledgerbankDetailsRepository;
    @Autowired
    private LedgerTransactionPostingsRepository ledgerTransactionPostingsRepository;

    private static final Logger ledgerLogger = LogManager.getLogger(LedgerMasterService.class);
    @Autowired
    private UsersRepository usersRepository;
   /* @Autowired
    private TranxPurInvoiceRepository tranxPurInvoiceRepository;*/


    static String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    @Autowired
    private AreaMasterRepository areaMasterRepository;

    static String num_hash(int num) {
        if (num < 26) return Character.toString(alpha.charAt(num - 1));
        else {
            int q = Math.floorDiv(num, 26);
            int r = num % 26;
            if (r == 0) {
                if (q == 1) {
                    return Character.toString(alpha.charAt((26 + r - 1) % 26));
                } else return num_hash(q - 1) + alpha.charAt((26 + r - 1) % 26);
            } else return num_hash(q) + alpha.charAt((26 + r - 1) % 26);
        }
    }


    public Object createLedgerMaster(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        LedgerMaster lMaster = null;
        LedgerMaster mLedger = null;
        LedgerMaster lMaster1 = null;
        ResponseMessage responseMessage = new ResponseMessage();
        LedgerMaster ledgerMaster = new LedgerMaster();
        mLedger = ledgerCreateUpdate(request, "create", ledgerMaster);

        if (mLedger != null) {
//                insertIntoLedgerBalanceSummary(mLedger, "create");
            responseMessage.setMessage("Ledger created successfully");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        } else {
            responseMessage.setMessage("Error in ledger creation");
            responseMessage.setResponseStatus(HttpStatus.FORBIDDEN.value());
        }
         /*else {
            System.out.println("Already Ledger created with this name or code");
            responseMessage.setMessage("Already Ledger created..");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        }*/
        return responseMessage;
    }

    public LedgerMaster ledgerCreateUpdate(HttpServletRequest request, String key, LedgerMaster ledgerMaster) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        PrincipleGroups groups = null;
        Principles principles = null;
        Foundations foundations = null;
        State mState = null;
        Country mCountry = null;
        LedgerMaster mLedger = null;
        if (paramMap.containsKey("principle_id")) {
            principles = principleRepository.findByIdAndStatus(Long.parseLong(request.getParameter("principle_id")), true);
//            principles = principleRepository.findByIdAndStatus(Long.parseLong(request.getParameter("principle_id")), true);
            foundations = principles.getFoundations();
        }
        if (paramMap.containsKey("principle_group_id")) {
            groups = principleGroupsRepository.findByIdAndStatus(Long.parseLong(request.getParameter("principle_group_id")), true);
        }
        /***** Associate Group if available ******/
        if (paramMap.containsKey("associates_id") && !request.getParameter("associates_id").equalsIgnoreCase("")) {
            AssociateGroups associateGroups = associateGroupsRepository.findByIdAndStatus(Long.parseLong(request.getParameter("associates_id")), true);
            if (associateGroups != null) ledgerMaster.setAssociateGroups(associateGroups);
        }
        if (groups != null) {
            ledgerMaster.setPrincipleGroups(groups);
            ledgerMaster.setPrinciples(principles);
            ledgerMaster.setUniqueCode(groups.getUniqueCode());
        } else {
            ledgerMaster.setPrincipleGroups(groups);
            ledgerMaster.setPrinciples(principles);
            ledgerMaster.setUniqueCode(principles.getUniqueCode());
        }
        if (foundations != null) ledgerMaster.setFoundations(foundations);
        if (paramMap.containsKey("is_private"))
            ledgerMaster.setIsPrivate(Boolean.parseBoolean(request.getParameter("is_private")));
        if (key.equalsIgnoreCase("create")) {
            ledgerMaster.setIsDeleted(true); //isDelete : true means , we can delete this ledger
            // if it is not involved into any tranxs
            ledgerMaster.setStatus(true);
            ledgerMaster.setIsDefaultLedger(false);
        }
        if (users.getBranch() != null) ledgerMaster.setBranch(users.getBranch());
        ledgerMaster.setCompany(users.getCompany());
        ledgerMaster.setCreatedBy(users.getId());
        ledgerMaster.setLedgerName(request.getParameter("ledger_name"));
        if (paramMap.containsKey("slug")) ledgerMaster.setSlugName(request.getParameter("slug"));
        else ledgerMaster.setSlugName("");
        if (paramMap.containsKey("under_prefix")) ledgerMaster.setUnderPrefix(request.getParameter("under_prefix"));
        else ledgerMaster.setUnderPrefix("");
        if (request.getParameter("slug").equalsIgnoreCase("sundry_creditors") || request.getParameter("slug").equalsIgnoreCase("sundry_debtors")) {
            ledgerMaster.setTaxType("");
            if (paramMap.containsKey("supplier_code")) {
                if (request.getParameter("supplier_code").equalsIgnoreCase("")) ledgerMaster.setLedgerCode(null);
                else ledgerMaster.setLedgerCode(request.getParameter("supplier_code"));
            }

        /*    if (paramMap.containsKey("sales_rate")) {
                ledgerMaster.setSalesRate(Double.valueOf(request.getParameter("sales_rate")));
            }*/
            if (paramMap.containsKey("mailing_name")) {
                ledgerMaster.setMailingName(request.getParameter("mailing_name"));
            } else {
                ledgerMaster.setMailingName("");
            }

            if (paramMap.containsKey("route")) {
                ledgerMaster.setRoute(request.getParameter("route"));
            } else {
                ledgerMaster.setRoute(null);
            }
//            if (paramMap.containsKey("salesman")) {
//                SalesManMaster salesManMaster = salesmanMasterRepository.findByIdAndStatus(
//                        Long.parseLong(request.getParameter("salesman")), true);
//                ledgerMaster.setColumnA(request.getParameter("salesman"));  //columnA= salesman
//                ledgerMaster.setSalesmanId(salesManMaster.getId());
//            }
//            if (paramMap.containsKey("area")) {
//                AreaMaster areaMaster = areaMasterRepository.findByIdAndStatus(
//                        Long.parseLong(request.getParameter("area")), true);
//                ledgerMaster.setArea(request.getParameter("area"));  //columnA= salesman
//                ledgerMaster.setAreaId(areaMaster.getId());
//            }
            if (paramMap.containsKey("opening_bal_type")) {
                ledgerMaster.setOpeningBalType(request.getParameter("opening_bal_type"));
            } else {
                ledgerMaster.setOpeningBalType("");
            }
            if (paramMap.containsKey("balancing_method")) {
                BalancingMethod balancingMethod = balancingMethodRepository.findByIdAndStatus(Long.parseLong(request.getParameter("balancing_method")), true);
                ledgerMaster.setBalancingMethod(balancingMethod);
            }
            if (paramMap.containsKey("address")) {
                ledgerMaster.setAddress(request.getParameter("address"));
            } else {
                ledgerMaster.setAddress("");
            }
            if (paramMap.containsKey("state")) {
                Optional<State> state = stateRepository.findById(Long.parseLong(request.getParameter("state")));
                mState = state.get();
                ledgerMaster.setState(mState);
            }
            if (paramMap.containsKey("country")) {
                Optional<Country> country = countryRepository.findById(Long.parseLong(request.getParameter("country")));
                mCountry = country.get();
                ledgerMaster.setCountry(mCountry);
            }
            if (paramMap.containsKey("pincode") && !request.getParameter("pincode").equalsIgnoreCase("")) {
//                ledgerMaster.setPincode(Long.parseLong(request.getParameter("pincode").trim()));
                ledgerMaster.setPincode(Long.valueOf(request.getParameter("pincode")));

            }/* else {
                ledgerMaster.setPincode(0L);
            }*/
            if (paramMap.containsKey("city")) {
                ledgerMaster.setCity(request.getParameter("city").trim());
            } else {
                ledgerMaster.setCity("");
            }
            if (paramMap.containsKey("email")) {
                ledgerMaster.setEmail(request.getParameter("email"));
            }
            if (paramMap.containsKey("mobile_no")) {
                ledgerMaster.setMobile(Long.parseLong(request.getParameter("mobile_no").trim()));
            }
            ledgerMaster.setTaxable(Boolean.parseBoolean(request.getParameter("taxable")));
            if (Boolean.parseBoolean(request.getParameter("taxable"))) {
                Long registraton_type = Long.valueOf(request.getParameter("registration_type"));
//                GstTypeMaster gstTypeMaster = gstMasterRepository.findById(registraton_type).get();
                GstTypeMaster gstTypeMaster = gstMasterRepository.findById(Long.valueOf(request.getParameter("registration_type"))).get();

                ledgerMaster.setRegistrationType(gstTypeMaster.getId());
            } else {
                GstTypeMaster gstTypeMaster = gstMasterRepository.findById(3L).get();
                ledgerMaster.setRegistrationType(gstTypeMaster.getId());
                if (mState != null) ledgerMaster.setStateCode(mState.getStateCode());
                if (paramMap.containsKey("pan_no")) {
                    ledgerMaster.setPancard(request.getParameter("pan_no"));
                } else {
                    ledgerMaster.setPancard("");
                }
            }
            if (request.getParameter("slug").equalsIgnoreCase("sundry_creditors")) {
                if (paramMap.containsKey("bank_name")) ledgerMaster.setBankName(request.getParameter("bank_name"));
                else ledgerMaster.setBankName("");
                if (paramMap.containsKey("account_no"))
                    ledgerMaster.setAccountNumber(request.getParameter("account_no"));
                else ledgerMaster.setAccountNumber("");
                if (paramMap.containsKey("ifsc_code")) ledgerMaster.setIfsc(request.getParameter("ifsc_code"));
                else ledgerMaster.setIfsc("");
                if (paramMap.containsKey("bank_branch"))
                    ledgerMaster.setBankBranch(request.getParameter("bank_branch"));
                else ledgerMaster.setBankBranch("");
                if (paramMap.containsKey("opening_bal")) {
                    if (request.getParameter("opening_bal_type").equalsIgnoreCase("Cr")) {
                        ledgerMaster.setOpeningBal(Double.parseDouble(request.getParameter("opening_bal").trim()));
                    } else {
                        Double openingBal = Double.parseDouble(request.getParameter("opening_bal").trim());
                        openingBal *= -1;
                        ledgerMaster.setOpeningBal(openingBal);
                    }
                }
            } else {
                ledgerMaster.setBankName("");
                ledgerMaster.setAccountNumber("");
                ledgerMaster.setIfsc("");
                ledgerMaster.setBankBranch("");
                if (paramMap.containsKey("opening_bal")) {
                    if (request.getParameter("opening_bal_type").equalsIgnoreCase("Dr")) {
                        Double openingBal = Double.parseDouble(request.getParameter("opening_bal").trim());
                        openingBal *= -1;
                        ledgerMaster.setOpeningBal(openingBal);
                    } else {
                        ledgerMaster.setOpeningBal(Double.parseDouble(request.getParameter("opening_bal").trim()));
                    }
                }
            }
            /* pune demo visit changes */
            if (paramMap.containsKey("credit_days")) {
                ledgerMaster.setCreditDays(Integer.parseInt(request.getParameter("credit_days").trim()));
                ledgerMaster.setApplicableFrom(request.getParameter("applicable_from"));
            } else {
                ledgerMaster.setCreditDays(0);
                ledgerMaster.setApplicableFrom("");
            }
            if (paramMap.containsKey("fssai")) ledgerMaster.setFoodLicenseNo(request.getParameter("fssai"));
            else ledgerMaster.setFoodLicenseNo("");
            if (paramMap.containsKey("foodLicenseExpiryDate"))
                ledgerMaster.setFssaiExpiry(LocalDate.parse(request.getParameter("foodLicenseExpiryDate")));
            if (paramMap.containsKey("tds")) ledgerMaster.setTds(Boolean.parseBoolean(request.getParameter("tds")));
            if (paramMap.containsKey("tds_applicable_date"))
                ledgerMaster.setTdsApplicableDate(LocalDate.parse(request.getParameter("tds_applicable_date")));
            if (paramMap.containsKey("tcs")) ledgerMaster.setTcs(Boolean.parseBoolean(request.getParameter("tcs")));
            if (paramMap.containsKey("tcs_applicable_date"))
                ledgerMaster.setTcsApplicableDate(LocalDate.parse(request.getParameter("tcs_applicable_date")));
            if (paramMap.containsKey("area")) ledgerMaster.setArea(request.getParameter("area"));
            if (paramMap.containsKey("landmark")) ledgerMaster.setArea(request.getParameter("landmark"));
            if (paramMap.containsKey("salesrate"))
                ledgerMaster.setSalesRate(Double.parseDouble(request.getParameter("salesrate")));
            if (paramMap.containsKey("drug_license_no"))
                ledgerMaster.setDrugLicenseNo(request.getParameter("drug_license_no"));
            if (paramMap.containsKey("drug_expiry"))
                ledgerMaster.setDrugExpiry(LocalDate.parse(request.getParameter("drug_expiry")));

            /****** Modification after PK visits at Solapur 25th to 30th January 2023 ******/
            if (paramMap.containsKey("licenseNo")) {
                ledgerMaster.setLicenseNo(request.getParameter("licenseNo"));
            }
            if (paramMap.containsKey("licenseExpiryDate")) {
                ledgerMaster.setLicenseExpiry(LocalDate.parse(request.getParameter("licenseExpiryDate")));
            }
            /*if (paramMap.containsKey("foodLicenseExpiryDate")) {
                ledgerMaster.setFoodLicenseExpiry(LocalDate.parse(request.getParameter("foodLicenseExpiryDate")));
            }*/
            if (paramMap.containsKey("manufacturingLicenseNo")) {
                ledgerMaster.setManufacturingLicenseNo(request.getParameter("manufacturingLicenseNo"));
            }
            if (paramMap.containsKey("manufacturingLicenseExpiry")) {
                ledgerMaster.setManufacturingLicenseExpiry(LocalDate.parse(request.getParameter("manufacturingLicenseExpiry")));
            }
            if (paramMap.containsKey("gstTransferDate"))
                ledgerMaster.setGstTransferDate(LocalDate.parse(request.getParameter("gstTransferDate")));
            if (paramMap.containsKey("place")) ledgerMaster.setPlace(request.getParameter("place"));
            if (paramMap.containsKey("route")) ledgerMaster.setRoute(request.getParameter("route"));
            if (paramMap.containsKey("district")) ledgerMaster.setDistrict(request.getParameter("district"));
            if (paramMap.containsKey("businessType"))
                ledgerMaster.setBusinessType(request.getParameter("businessType"));
            if (paramMap.containsKey("businessTrade"))
                ledgerMaster.setBusinessTrade(request.getParameter("businessTrade"));
            if (paramMap.containsKey("creditNumBills"))
                ledgerMaster.setCreditNumBills(Double.parseDouble(request.getParameter("creditNumBills")));
            if (paramMap.containsKey("creditBillValue"))
                ledgerMaster.setCreditBillValue(Double.parseDouble(request.getParameter("creditBillValue")));
            if (paramMap.containsKey("lrBillDate"))
                ledgerMaster.setLrBillDate(LocalDate.parse(request.getParameter("lrBillDate")));
            if (paramMap.containsKey("creditBillDate"))
                ledgerMaster.setCreditBillDate(LocalDate.parse(request.getParameter("creditBillDate")));
            if (paramMap.containsKey("anniversary"))
                ledgerMaster.setAnniversary(LocalDate.parse(request.getParameter("anniversary")));
            if (paramMap.containsKey("dob")) ledgerMaster.setDob(LocalDate.parse(request.getParameter("dob")));
            /*** END ****/
        } else if (request.getParameter("slug").equalsIgnoreCase("bank_account")) {
            if (paramMap.containsKey("opening_bal_type")) {
                ledgerMaster.setOpeningBalType(request.getParameter("opening_bal_type"));
            }
            if (paramMap.containsKey("opening_bal")) {
                if (request.getParameter("opening_bal_type").equalsIgnoreCase("Dr")) {
                    Double openingBal = Double.parseDouble(request.getParameter("opening_bal"));
                    openingBal *= -1;
                    ledgerMaster.setOpeningBal(openingBal);
                } else {
                    ledgerMaster.setOpeningBal(Double.parseDouble(request.getParameter("opening_bal")));
                }
            }
            if (paramMap.containsKey("state")) {
                Optional<State> state = stateRepository.findById(Long.parseLong(request.getParameter("state")));
                mState = state.get();
                ledgerMaster.setState(mState);
            }
            if (paramMap.containsKey("country")) {
                Optional<Country> country = countryRepository.findById(Long.parseLong(request.getParameter("country")));
                mCountry = country.get();
                ledgerMaster.setCountry(mCountry);
            }
            if (paramMap.containsKey("pincode")) {
                ledgerMaster.setPincode(Long.parseLong(request.getParameter("pincode").trim()));
            }
            if (paramMap.containsKey("email")) {
                ledgerMaster.setEmail(request.getParameter("email"));
            }
            if (paramMap.containsKey("address")) {
                ledgerMaster.setAddress(request.getParameter("address"));
            } else {
                ledgerMaster.setAddress("");
            }
            if (paramMap.containsKey("mobile_no")) {
                ledgerMaster.setMobile(Long.parseLong(request.getParameter("mobile_no").trim()));
            }
//            ledgerMaster.setTaxable(Boolean.parseBoolean(request.getParameter("taxable")));
//            if (Boolean.parseBoolean(request.getParameter("taxable"))) {
//                ledgerMaster.setGstin(request.getParameter("gstin"));
//                if (paramMap.containsKey("gstType")) {
//                    GstTypeMaster gstTypeMaster = gstMasterRepository.findById(Long.parseLong(request.getParameter("gstType"))).get();
//                    ledgerMaster.setRegistrationType(gstTypeMaster.getId());
//                }
//            } else {
//                GstTypeMaster gstTypeMaster = gstMasterRepository.findById(3L).get();
//                ledgerMaster.setRegistrationType(gstTypeMaster.getId());
//            }
            if (paramMap.containsKey("pan_no")) {
                ledgerMaster.setPancard(request.getParameter("pan_no"));
            } else {
                ledgerMaster.setPancard("");
            }
            if (paramMap.containsKey("bank_name")) ledgerMaster.setBankName(request.getParameter("bank_name"));
            else ledgerMaster.setBankName("");
            if (paramMap.containsKey("account_no")) ledgerMaster.setAccountNumber(request.getParameter("account_no"));
            else ledgerMaster.setAccountNumber("");
            if (paramMap.containsKey("ifsc_code")) ledgerMaster.setIfsc(request.getParameter("ifsc_code"));
            else ledgerMaster.setIfsc("");
            if (paramMap.containsKey("bank_branch")) ledgerMaster.setBankBranch(request.getParameter("bank_branch"));
            else ledgerMaster.setBankBranch("");
            ledgerMaster.setMailingName("");
            ledgerMaster.setStateCode("");
        } else if (request.getParameter("slug").equalsIgnoreCase("duties_taxes")) {
            ledgerMaster.setTaxType(request.getParameter("tax_type"));
            ledgerMaster.setMailingName("");
            if (paramMap.containsKey("opening_bal_type")) {
                ledgerMaster.setOpeningBalType(request.getParameter("opening_bal_type"));
            }
            if (paramMap.containsKey("opening_bal")) {
                if (request.getParameter("opening_bal_type").equalsIgnoreCase("Dr")) {
                    ledgerMaster.setOpeningBal(Double.parseDouble(request.getParameter("opening_bal").trim()));
                } else {
                    Double openingBal = Double.parseDouble(request.getParameter("opening_bal").trim());
                    openingBal *= -1;
                    ledgerMaster.setOpeningBal(openingBal);
                }
            }

            ledgerMaster.setAddress("");

            ledgerMaster.setTaxable(false);
            ledgerMaster.setGstin("");
            ledgerMaster.setRegistrationType(0L);
            ledgerMaster.setPancard("");
            ledgerMaster.setBankName("");
            ledgerMaster.setAccountNumber("");
            ledgerMaster.setIfsc("");
            ledgerMaster.setBankBranch("");
            ledgerMaster.setStateCode("");
        } else if (request.getParameter("slug").equalsIgnoreCase("others")) {
            if (paramMap.containsKey("pincode")) {
                ledgerMaster.setPincode(Long.parseLong(request.getParameter("pincode").trim()));
            } /*else {
                ledgerMaster.setPincode(0L);
            }*/
            if (paramMap.containsKey("address")) {
                ledgerMaster.setAddress(request.getParameter("address"));
            } else {
                ledgerMaster.setAddress("");
            }
            if (paramMap.containsKey("mobile_no")) {
                ledgerMaster.setMobile(Long.parseLong(request.getParameter("mobile_no").trim()));
            } /*else {
                ledgerMaster.setMobile(0L);
            }*/
            if (paramMap.containsKey("opening_bal_type")) {
                ledgerMaster.setOpeningBalType(request.getParameter("opening_bal_type"));
            }
            if (paramMap.containsKey("opening_bal")) {
                if (request.getParameter("opening_bal_type").equalsIgnoreCase("Dr")) {
                    ledgerMaster.setOpeningBal(Double.parseDouble(request.getParameter("opening_bal").trim()));
                } else {
                    Double openingBal = Double.parseDouble(request.getParameter("opening_bal").trim());
                    openingBal *= -1;
                    ledgerMaster.setOpeningBal(openingBal);
                }
            }
            ledgerMaster.setTaxType("");
            ledgerMaster.setMailingName("");
//            ledgerMaster.setOpeningBalType("");
//            ledgerMaster.setOpeningBal(0.0);
            // ledgerMaster.setEmail("");
            ledgerMaster.setTaxable(false);
            ledgerMaster.setGstin("");
            ledgerMaster.setRegistrationType(0L);
            ledgerMaster.setPancard("");
            ledgerMaster.setBankName("");
            ledgerMaster.setAccountNumber("");
            ledgerMaster.setIfsc("");
            ledgerMaster.setBankBranch("");
            ledgerMaster.setStateCode("");
        } else if (request.getParameter("slug").equalsIgnoreCase("assets")) {
            if (paramMap.containsKey("opening_bal_type")) {
                ledgerMaster.setOpeningBalType(request.getParameter("opening_bal_type"));
            } else {
                ledgerMaster.setOpeningBalType("");
            }
            if (paramMap.containsKey("opening_bal")) {
                if (request.getParameter("opening_bal_type").equalsIgnoreCase("Dr")) {
                    ledgerMaster.setOpeningBal(Double.parseDouble(request.getParameter("opening_bal").trim()));
                } else {
                    Double openingBal = Double.parseDouble(request.getParameter("opening_bal").trim());
                    openingBal *= -1;
                    ledgerMaster.setOpeningBal(openingBal);
                }
            }
            ledgerMaster.setTaxType("");
            ledgerMaster.setMailingName("");
            //  ledgerMaster.setEmail("");
            ledgerMaster.setTaxable(false);
            ledgerMaster.setGstin("");
            ledgerMaster.setRegistrationType(0L);
            ledgerMaster.setPancard("");
            ledgerMaster.setBankName("");
            ledgerMaster.setAccountNumber("");
            ledgerMaster.setIfsc("");
            ledgerMaster.setBankBranch("");
            ledgerMaster.setStateCode("");
            ledgerMaster.setAddress("");
          /*  ledgerMaster.setPincode(0L);
            ledgerMaster.setMobile(0l);*/
        }
        try {
            mLedger = repository.save(ledgerMaster);///automatic trigger call : balance summary
            if (mLedger.getLedgerCode() == null && (mLedger.getUniqueCode().equalsIgnoreCase("SUCR") || mLedger.getUniqueCode().equalsIgnoreCase("SUDR"))) {
                long indexofLedger = 0;
                indexofLedger = mLedger.getId();
                String ans = num_hash((int) indexofLedger);
                mLedger.setLedgerCode(ans);
                repository.save(mLedger);
            }

            LedgerBalanceSummary mBalance = null;
            if (key.equalsIgnoreCase("edit")) {
                mBalance = balanceSummaryRepository.findByLedgerMasterId(mLedger.getId());
                mBalance.setPrinciples(mLedger.getPrinciples());
                mBalance.setFoundations(mLedger.getFoundations());
                mBalance.setPrincipleGroups(mLedger.getPrincipleGroups());
                mBalance.setOpeningBal(mLedger.getOpeningBal());
                mBalance.setUnderPrefix(mLedger.getUnderPrefix());

                try {
                    balanceSummaryRepository.save(mBalance);
                } catch (Exception e) {
                    ledgerLogger.error("Exception in ledgerCreateUpdate:" + e.getMessage());
                    //e.printStackTrace();
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            System.out.println("exceptions" + e.getMessage());
            ledgerLogger.error("Exception in ledgerCreateUpdate:" + e.getMessage());
            //e.printStackTrace();
            e.printStackTrace();
        }
        if (paramMap.containsKey("gstdetails")) {
            if (key.equalsIgnoreCase("create")) insertIntoGstDetails(mLedger, request);
            else updateGstDetails(mLedger, request);
        }
        if (paramMap.containsKey("shippingDetails")) {
            if (key.equalsIgnoreCase("create")) insertIntoShippingDetails(mLedger, request);
            else updateShippingDetails(mLedger, request);
        }
        if (paramMap.containsKey("deptDetails")) {
            if (key.equalsIgnoreCase("create"))
                insertIntoDeptDetails(mLedger, request);
            else
                updateDeptDetails(mLedger, request);
        }
        if (paramMap.containsKey("billingDetails")) {
            if (key.equalsIgnoreCase("create")) insertIntoBillingDetails(mLedger, request);
            else updateBillingDetails(mLedger, request);
        }
        if (paramMap.containsKey("bankDetails")) {
            if (key.equalsIgnoreCase("create")) insertIntobankDetails(mLedger, request);
            else updateBankDetails(mLedger, request);
        }
        return mLedger;
    }

    private void updateBankDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("bankDetails");
        JsonParser parser = new JsonParser();
        JsonElement bankElements = parser.parse(strJson);
        JsonArray bankDetailsJson = bankElements.getAsJsonArray();
        LedgerBankDetails bankDetails = null;
        Map<String, String[]> paramMap = request.getParameterMap();
        if (bankDetailsJson.size() > 0) {
            for (JsonElement mList : bankDetailsJson) {
                JsonObject object = mList.getAsJsonObject();
                if (object.get("bid").getAsLong() > 0) {
                    bankDetails = ledgerbankDetailsRepository.findByIdAndStatus(object.get("bid").getAsLong(), true);
                } else {
                    bankDetails = new LedgerBankDetails();
                    bankDetails.setStatus(true);
                }
                bankDetails.setBankName(object.get("bank_name").getAsString());
                bankDetails.setAccountNo(object.get("bank_account_no").getAsString());
                bankDetails.setIfsc(object.get("bank_ifsc_code").getAsString());
                bankDetails.setBankBranch(object.get("bank_branch").getAsString());
                bankDetails.setCreatedBy(mLedger.getCreatedBy());
                bankDetails.setLedgerMaster(mLedger);
                ledgerbankDetailsRepository.save(bankDetails);
            }
        }
        /* Remove from existing and set status false */
        if (paramMap.containsKey("removeBankList")) {
            String removeBankDetails = request.getParameter("removeBankList");
            JsonElement removeBankElements = parser.parse(removeBankDetails);
            JsonArray removeDeptJson = removeBankElements.getAsJsonArray();
            LedgerBankDetails mBankDetails = null;
            if (removeDeptJson.size() > 0) {
                for (JsonElement mList : removeDeptJson) {
                    Long object = mList.getAsLong();
                    if (object != 0) {
                        mBankDetails = ledgerbankDetailsRepository.findByIdAndStatus(object, true);
                        if (mBankDetails != null) mBankDetails.setStatus(false);
                        try {
                            ledgerbankDetailsRepository.save(mBankDetails);
                        } catch (Exception e) {
                            e.printStackTrace();
                            ledgerLogger.error("Exception in updateDeptDetails:" + e.getMessage());
                            System.out.println("Exception:" + e.getMessage());
                            e.getMessage();
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    }

    private void updateBillingDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("billingDetails");
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray billDetailsJson = gstElements.getAsJsonArray();
        LedgerBillingDetails billDetails = null;
        Map<String, String[]> paramMap = request.getParameterMap();
        if (billDetailsJson.size() > 0) {
            for (JsonElement mList : billDetailsJson) {
                JsonObject object = mList.getAsJsonObject();
                if (object.get("id").getAsLong() != 0) {
                    billDetails = ledgerBillingDetailsRepository.findByIdAndStatus(object.get("id").getAsLong(), true);
                } else {
                    billDetails = new LedgerBillingDetails();
                    billDetails.setStatus(true);
                }
                billDetails.setDistrict(object.get("district").getAsString());
                billDetails.setBillingAddress(object.get("billing_address").getAsString());
                billDetails.setCreatedBy(mLedger.getCreatedBy());
                billDetails.setLedgerMaster(mLedger);
                ledgerBillingDetailsRepository.save(billDetails);
            }
        }
        /* Remove from existing and set status false */
        if (paramMap.containsKey("removeBillingList")) {
            String removeBillingDetails = request.getParameter("removeBillingList");
            JsonElement removeBillingElements = parser.parse(removeBillingDetails);
            JsonArray removeBillingJson = removeBillingElements.getAsJsonArray();
            LedgerBillingDetails mDeptDetails = null;
            if (removeBillingJson.size() > 0) {
                for (JsonElement mList : removeBillingJson) {
                    Long object = mList.getAsLong();
                    if (object != 0) {
                        mDeptDetails = ledgerBillingDetailsRepository.findByIdAndStatus(object, true);
                        if (mDeptDetails != null) mDeptDetails.setStatus(false);
                        try {
                            ledgerBillingDetailsRepository.save(mDeptDetails);
                        } catch (Exception e) {
                            e.printStackTrace();
                            ledgerLogger.error("Exception in updateBillingDetails:" + e.getMessage());
                            System.out.println("Exception:" + e.getMessage());
                            e.getMessage();
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    }

    private void updateDeptDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("deptDetails");
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray deptDetailsJson = gstElements.getAsJsonArray();
        LedgerDeptDetails deptDetails = null;
        Map<String, String[]> paramMap = request.getParameterMap();
        if (deptDetailsJson.size() > 0) {
            for (JsonElement mList : deptDetailsJson) {
                JsonObject object = mList.getAsJsonObject();
                if (object.get("did").getAsLong() > 0) {
                    deptDetails = ledgerDeptDetailsRepository.findByIdAndStatus(object.get("did").getAsLong(), true);
                } else {
                    deptDetails = new LedgerDeptDetails();
                    deptDetails.setStatus(true);
                }
                deptDetails.setDept(object.get("dept").getAsString());
                deptDetails.setContactPerson(object.get("contact_person").getAsString());
                if (object.has("email")) deptDetails.setEmail(object.get("email").getAsString());
                else deptDetails.setEmail("");
                if (object.has("contact_no") &&
                        !object.get("contact_no").getAsString().equalsIgnoreCase(""))
                    deptDetails.setContactNo(object.get("contact_no").getAsLong());
                deptDetails.setCreatedBy(mLedger.getCreatedBy());
                deptDetails.setLedgerMaster(mLedger);
                ledgerDeptDetailsRepository.save(deptDetails);
            }
        }
        /* Remove from existing and set status false */
        if (paramMap.containsKey("removeDeptList")) {
            String removeDeptDetails = request.getParameter("removeDeptList");
            JsonElement removeDeptElements = parser.parse(removeDeptDetails);
            JsonArray removeDeptJson = removeDeptElements.getAsJsonArray();
            LedgerDeptDetails mDeptDetails = null;
            if (removeDeptJson.size() > 0) {
                for (JsonElement mList : removeDeptJson) {
                    Long object = mList.getAsLong();
                    if (object != 0) {
                        mDeptDetails = ledgerDeptDetailsRepository.findByIdAndStatus(object, true);
                        if (mDeptDetails != null) mDeptDetails.setStatus(false);
                        try {
                            ledgerDeptDetailsRepository.save(mDeptDetails);
                        } catch (Exception e) {
                            e.printStackTrace();
                            ledgerLogger.error("Exception in updateDeptDetails:" + e.getMessage());
                            System.out.println("Exception:" + e.getMessage());
                            e.getMessage();
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    }

    private void updateShippingDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("shippingDetails");
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray shippingDetailsJson = gstElements.getAsJsonArray();
        LedgerShippingAddress spDetails = null;

        if (shippingDetailsJson.size() > 0) {
            for (JsonElement mList : shippingDetailsJson) {
                JsonObject object = mList.getAsJsonObject();
                if (object.get("sid").getAsLong() > 0) {

                    spDetails = ledgerShippingDetailsRepository.findByIdAndStatus(object.get("sid").getAsLong(), true);
                } else {
                    spDetails = new LedgerShippingAddress();
                    spDetails.setStatus(true);
                }
                spDetails.setDistrict(object.get("district").getAsString());
                spDetails.setShippingAddress(object.get("shipping_address").getAsString());
                spDetails.setCreatedBy(mLedger.getCreatedBy());
                spDetails.setLedgerMaster(mLedger);
                ledgerShippingDetailsRepository.save(spDetails);
            }
        }
        /* Remove from existing and set status false */
        if (paramMap.containsKey("removeShippingList")) {
            String removeShippingDetails = request.getParameter("removeShippingList");
            JsonElement removeShippingElements = parser.parse(removeShippingDetails);
            JsonArray removeShippingJson = removeShippingElements.getAsJsonArray();
            LedgerShippingAddress mShippingDetails = null;
            if (removeShippingJson.size() > 0) {
                for (JsonElement mList : removeShippingJson) {
                    Long object = mList.getAsLong();
                    if (object != 0) {
                        mShippingDetails = ledgerShippingDetailsRepository.findByIdAndStatus(object, true);
                        if (mShippingDetails != null) mShippingDetails.setStatus(false);
                        try {
                            ledgerShippingDetailsRepository.save(mShippingDetails);
                        } catch (Exception e) {
                            e.printStackTrace();
                            ledgerLogger.error("Exception in updateShippingDetails:" + e.getMessage());
                            System.out.println("Exception:" + e.getMessage());
                            e.getMessage();
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    }

    private void insertIntobankDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("bankDetails");
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray bankDetailsJson = gstElements.getAsJsonArray();
        if (bankDetailsJson.size() > 0) {
            for (JsonElement mList : bankDetailsJson) {
                JsonObject object = mList.getAsJsonObject();

                LedgerBankDetails bankDetails = new LedgerBankDetails();
                bankDetails.setStatus(true);

                bankDetails.setBankName(object.get("bank_name").getAsString());
                bankDetails.setAccountNo(object.get("bank_account_no").getAsString());
                bankDetails.setIfsc(object.get("bank_ifsc_code").getAsString());
                bankDetails.setBankBranch(object.get("bank_branch").getAsString());
                bankDetails.setCreatedBy(mLedger.getCreatedBy());
                bankDetails.setLedgerMaster(mLedger);
                ledgerbankDetailsRepository.save(bankDetails);
            }
        }
    }


    private void updateGstDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("gstdetails");
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray gstDetailsJson = gstElements.getAsJsonArray();
        LedgerGstDetails gstDetails = null;
        if (gstDetailsJson.size() > 0) {
            for (JsonElement mList : gstDetailsJson) {
                JsonObject object = mList.getAsJsonObject();

                if (object.get("bid").getAsLong() > 0) {
                    gstDetails = ledgerGstDetailsRepository.findByIdAndStatus(object.get("bid").getAsLong(), true);
                } else {
                    gstDetails = new LedgerGstDetails();
                    gstDetails.setStatus(true);
                }
                gstDetails.setGstin(object.get("gstin").getAsString());
                if (object.has("dateofregistartion"))
                    gstDetails.setDateOfRegistration(LocalDate.parse(object.get("dateofregistartion").getAsString()));
                if (object.has("pancard")) gstDetails.setPanCard(object.get("pancard").getAsString());
                else {
                    gstDetails.setPanCard("");
                }

                String stateCode = object.get("gstin").getAsString().substring(0, 2);
                gstDetails.setStateCode(stateCode);
                gstDetails.setCreatedBy(mLedger.getCreatedBy());
                gstDetails.setLedgerMaster(mLedger);
                try {
                    ledgerGstDetailsRepository.save(gstDetails);
                } catch (Exception e) {
                    e.printStackTrace();
                    ledgerLogger.error("Exception in updateGstDetails:" + e.getMessage());
                    System.out.println("Exception:" + e.getMessage());
                    e.getMessage();
                    e.printStackTrace();
                }
            }
        }
        /* Remove from existing and set status false */
        if (paramMap.containsKey("removeGstList")) {
            String removeGstDetails = request.getParameter("removeGstList");
            JsonElement removeGstElements = parser.parse(removeGstDetails);
            JsonArray removeGstJson = removeGstElements.getAsJsonArray();
            LedgerGstDetails mGstDetails = null;
            if (removeGstJson.size() > 0) {
                for (JsonElement mList : removeGstJson) {
                    Long object = mList.getAsLong();
                    if (object != 0) {
                        mGstDetails = ledgerGstDetailsRepository.findByIdAndStatus(object, true);
                        if (mGstDetails != null) mGstDetails.setStatus(false);
                        try {
                            ledgerGstDetailsRepository.save(mGstDetails);
                        } catch (Exception e) {
                            e.printStackTrace();
                            ledgerLogger.error("Exception in updateGstDetails:" + e.getMessage());
                            System.out.println("Exception:" + e.getMessage());
                            e.getMessage();
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
    }

    private void insertIntoBillingDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("billingDetails");
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray billDetailsJson = gstElements.getAsJsonArray();
        if (billDetailsJson.size() > 0) {
            for (JsonElement mList : billDetailsJson) {
                LedgerBillingDetails billDetails = new LedgerBillingDetails();
                JsonObject object = mList.getAsJsonObject();
                billDetails.setDistrict(object.get("district").getAsString());
                billDetails.setBillingAddress(object.get("billing_address").getAsString());
                billDetails.setCreatedBy(mLedger.getCreatedBy());
                billDetails.setStatus(true);
                billDetails.setLedgerMaster(mLedger);
                ledgerBillingDetailsRepository.save(billDetails);
            }
        }
    }

    private void insertIntoDeptDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("deptDetails");
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray deptDetailsJson = gstElements.getAsJsonArray();
        if (deptDetailsJson.size() > 0) {
            for (JsonElement mList : deptDetailsJson) {
                LedgerDeptDetails deptDetails = new LedgerDeptDetails();
                JsonObject object = mList.getAsJsonObject();
                deptDetails.setDept(object.get("dept").getAsString());
                deptDetails.setContactPerson(object.get("contact_person").getAsString());
                if (object.has("email")) deptDetails.setEmail(object.get("email").getAsString());
                else deptDetails.setEmail("");
                if (object.has("contact_no") &&
                        !object.get("contact_no").getAsString().equalsIgnoreCase(""))
                    deptDetails.setContactNo(object.get("contact_no").getAsLong());
                deptDetails.setCreatedBy(mLedger.getCreatedBy());
                deptDetails.setStatus(true);
                deptDetails.setLedgerMaster(mLedger);
                ledgerDeptDetailsRepository.save(deptDetails);
            }
        }
    }

    private void insertIntoShippingDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("shippingDetails");
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray shippingDetailsJson = gstElements.getAsJsonArray();
        if (shippingDetailsJson.size() > 0) {
            for (JsonElement mList : shippingDetailsJson) {
                LedgerShippingAddress spDetails = new LedgerShippingAddress();
                JsonObject object = mList.getAsJsonObject();
                spDetails.setDistrict(object.get("district").getAsString());
                spDetails.setShippingAddress(object.get("shipping_address").getAsString());
                spDetails.setCreatedBy(mLedger.getCreatedBy());
                spDetails.setStatus(true);
                spDetails.setLedgerMaster(mLedger);
                ledgerShippingDetailsRepository.save(spDetails);
            }
        }
    }

    private void insertIntoGstDetails(LedgerMaster mLedger, HttpServletRequest request) {
        String strJson = request.getParameter("gstdetails");
        JsonParser parser = new JsonParser();
        JsonElement gstElements = parser.parse(strJson);
        JsonArray gstDetailsJson = gstElements.getAsJsonArray();
        if (gstDetailsJson.size() > 0) {
            LedgerGstDetails gstDetails = null;
            for (JsonElement mList : gstDetailsJson) {
                JsonObject object = mList.getAsJsonObject();
                gstDetails = new LedgerGstDetails();
                gstDetails.setGstin(object.get("gstin").getAsString());
                if (object.has("dateofregistartion"))
                    gstDetails.setDateOfRegistration(LocalDate.parse(object.get("dateofregistartion").getAsString()));
                if (object.has("pancard")) gstDetails.setPanCard(object.get("pancard").getAsString());
                else {
                    gstDetails.setPanCard("");
                }
                String stateCode = object.get("gstin").getAsString().substring(0, 2);
                gstDetails.setStateCode(stateCode);
                gstDetails.setCreatedBy(mLedger.getCreatedBy());
                gstDetails.setStatus(true);
                gstDetails.setLedgerMaster(mLedger);
                try {
                    ledgerGstDetailsRepository.save(gstDetails);
                } catch (Exception e) {
                    System.out.println("Exception in insertIntoGstDetails" + e.getMessage());
                    e.getMessage();
                    e.printStackTrace();
                }
            }
        }
    }

    public void insertIntoLedgerBalanceSummary(LedgerMaster mLedger, String key) {
        LedgerBalanceSummary ledgerBalanceSummary = null;
        if (key.equalsIgnoreCase("create")) {
            ledgerBalanceSummary = new LedgerBalanceSummary();
        } /*else {
            ledgerBalanceSummary = balanceSummaryRepository.findByLedgerMasterId(mLedger.getId());
        }*/
        ledgerBalanceSummary.setLedgerMaster(mLedger);
        ledgerBalanceSummary.setFoundations(mLedger.getFoundations());
        ledgerBalanceSummary.setPrinciples(mLedger.getPrinciples());
        ledgerBalanceSummary.setPrincipleGroups(mLedger.getPrincipleGroups());
        ledgerBalanceSummary.setDebit(0.0);
        ledgerBalanceSummary.setCredit(0.0);
        ledgerBalanceSummary.setOpeningBal(mLedger.getOpeningBal());
        ledgerBalanceSummary.setClosingBal(0.0);
        ledgerBalanceSummary.setBalance(mLedger.getOpeningBal());
        ledgerBalanceSummary.setStatus(true);
        ledgerBalanceSummary.setUnderPrefix(mLedger.getUnderPrefix());
        try {
            balanceSummaryRepository.save(ledgerBalanceSummary);
        } catch (DataIntegrityViolationException e) {
            ledgerLogger.error("Exception in insertIntoLedgerBalanceSummary:" + e.getMessage());
            System.out.println(e.getMessage());
            e.printStackTrace();
        } catch (Exception e1) {
            e1.printStackTrace();
            ledgerLogger.error("Exception in insertIntoLedgerBalanceSummary:" + e1.getMessage());
            System.out.println(e1.getMessage());
            e1.printStackTrace();
        }
    }

    /* get Sundry Creditors Ledgers by outlet id */
    public JsonObject getSundryCreditors(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));


        List<Object[]> sundryCreditors = new ArrayList<>();
        if (users.getBranch() != null) {
            sundryCreditors = ledgerRepository.findSundryCreditorsByCompanyIdAndBranchId(users.getCompany().getId(), users.getBranch().getId());
        } else {
            sundryCreditors = ledgerRepository.findSundryCreditorsByCompanyId(users.getCompany().getId());
        }
        JsonArray result = new JsonArray();
        result = getResult(sundryCreditors);
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("message", "success");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        } else {
            response.addProperty("message", "empty");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        }
        return response;
    }

    public JsonArray getResult(List<Object[]> list) {
        JsonArray result = new JsonArray();
        for (int i = 0; i < list.size(); i++) {
            JsonObject response = new JsonObject();
            Object obj[] = list.get(i);
            response.addProperty("id", obj[0].toString());
            response.addProperty("name", obj[1].toString());
            if (obj[2] != null) response.addProperty("ledger_code", obj[2].toString());
            else response.addProperty("ledger_code", "");
            if (obj[3] != null) response.addProperty("state", obj[3].toString());
            response.addProperty("salesRate", 1);
            response.addProperty("isFirstDiscountPerCalculate", false);
            response.addProperty("takeDiscountAmountInLumpsum", false);
            if (obj[4] != null) {
                Double d = Double.parseDouble(obj[4].toString());
                response.addProperty("salesRate", d.intValue());
            }
            if (obj[5] != null) {
                response.addProperty("isFirstDiscountPerCalculate", Boolean.parseBoolean(obj[5].toString()));
            }
            if (obj[6] != null) {
                response.addProperty("takeDiscountAmountInLumpsum", Boolean.parseBoolean(obj[6].toString()));
            }
            response.add("gstDetails", getGSTDetails(Long.parseLong(obj[0].toString())));
            Long sundryCreditorId = Long.parseLong(obj[0].toString());
            Double balance = balanceSummaryRepository.findBalance(sundryCreditorId);
            if (balance != null) {
                if (balance > 0) {
                    response.addProperty("ledger_balance", balance);
                    response.addProperty("ledger_balance_type", "CR");
                } else {
                    response.addProperty("ledger_balance", Math.abs(balance));
                    response.addProperty("ledger_balance_type", "DR");

                }
            }
            result.add(response);
        }
        return result;
    }

    /* Get  */
    public JsonArray getGSTDetails(Long ledger_id) {

        JsonArray gstArray = new JsonArray();
        List<LedgerGstDetails> ledgerGstDetails = ledgerGstDetailsRepository.findByLedgerMasterIdAndStatus(ledger_id, true);
        for (LedgerGstDetails mDetails : ledgerGstDetails) {
            JsonObject mObject = new JsonObject();
            mObject.addProperty("id", mDetails.getId());
            mObject.addProperty("gstin", mDetails.getGstin());
            mObject.addProperty("state", mDetails.getStateCode());
            gstArray.add(mObject);
        }
        //    gstDetails.add("gstDetails",gstArray);
        return gstArray;
    }

    public JsonObject getSundryDebtors(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
//        List<Object[]> sundryDebtors = ledgerRepository.findSundryDebtorsByCompanyId(
//                users.getCompany().getId());
        List<Object[]> sundryDebtors = new ArrayList<>();
        if (users.getBranch() != null) {
            sundryDebtors = ledgerRepository.findSundryDebtorsByCompanyIdAndBranchId(users.getCompany().getId(), users.getBranch().getId());
        } else {
            sundryDebtors = ledgerRepository.findSundryDebtorsByCompanyId(users.getCompany().getId());
        }
        JsonArray result = new JsonArray();
        result = getResult(sundryDebtors);
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("message", "success");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        } else {
            response.addProperty("message", "empty");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        }
        return response;
    }

    /* get Purchase Account by outletId and principleId */
    public JsonObject getPurchaseAccount(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
     /*   if (users.getBranch() != null) {
            result = getLedgers("Purchase Accounts", users.getCompany().getId(), users.getBranch());
        } else {
            result = getLedgers("Purchase Accounts", users.getCompany().getId(), users.getBranch());
        }*/
        result = getLedgers("Purchase Accounts", users.getCompany().getId(), users.getBranch());
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("message", "success");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        } else {
            response.addProperty("message", "empty");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        }
        return response;
    }

    private JsonArray getLedgers(String key, Long outletId, Branch branch) {
        Principles principles = principleRepository.findByPrincipleNameIgnoreCaseAndStatus(key, true);
        List<LedgerMaster> indirect_incomes = new ArrayList<>();
        if (branch != null) {
            indirect_incomes = ledgerRepository.findByCompanyIdAndBranchIdAndPrinciplesIdAndStatus(outletId, branch.getId(), principles.getId(), true);

        } else {
            indirect_incomes = ledgerRepository.findByCompanyIdAndPrinciplesIdAndStatusAndBranchIsNull(outletId, principles.getId(), true);
        }
        JsonArray result = new JsonArray();
        for (LedgerMaster mAccount : indirect_incomes) {
            JsonObject response = new JsonObject();
            response.addProperty("id", mAccount.getId());
            response.addProperty("name", mAccount.getLedgerName());
            response.addProperty("unique_code", principles.getUniqueCode());
            result.add(response);
        }
        return result;
    }

    /* get Sales Account by outletId and principleId */
    public JsonObject getSalesAccount(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
//        result = getLedgers("Sales Accounts", users.getCompany().getId());
    /*    if (users.getBranch() != null) {
            result = getLedgers("Sales Accounts", users.getCompany().getId(), users.getBranch());
        } else {
            result = getLedgers("Sales Accounts", users.getCompany().getId(), users.getBranch());
        }*/
        result = getLedgers("Sales Accounts", users.getCompany().getId(), users.getBranch());
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("message", "success");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        } else {
            response.addProperty("message", "empty");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        }
        return response;
    }

    /* get All Indirect incomes by principleId(here principle id: 9 is for indirect incomes) */
    public JsonObject getIndirectIncomes(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
//        result = getLedgers("Indirect Income", users.getCompany().getId());
     /*   if (users.getBranch() != null) {
            result = getLedgers("Indirect Income", users.getCompany().getId(), users.getBranch());
        } else {
            result = getLedgers("Indirect Income", users.getCompany().getId(), users.getBranch());
        }*/
        result = getLedgers("Indirect Income", users.getCompany().getId(), users.getBranch());
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("message", "success");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        } else {
            response.addProperty("message", "empty");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        }
        return response;
    }

    /* get All Indirect expenses by principleId(here principle id: 9 is for indirect incomes) */
    public JsonObject getIndirectExpenses(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
//        result = getLedgers("Indirect Expenses", users.getCompany().getId());
      /*  if (users.getBranch() != null) {
            result = getLedgers("Indirect Expenses", users.getCompany().getId(), users.getBranch());
        } else {
            result = getLedgers("Indirect Expenses", users.getCompany().getId(), users.getBranch());
        }*/
        result = getLedgers("Indirect Expenses", users.getCompany().getId(), users.getBranch());
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("message", "success");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        } else {
            response.addProperty("message", "empty");
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.add("list", result);
        }
        return response;
    }

    public JsonObject getAllLedgers(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        Double closingBalance = 0.0;
        Double sumCR = 0.0;
        Double sumDR = 0.0;
        DecimalFormat df = new DecimalFormat("0.00");
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<LedgerMaster> balanceSummaries = new ArrayList<>();
        try{
            if (users.getIsAdmin()) {
                /**** Default ledgers for Branch Users *****/
                balanceSummaries = ledgerRepository.findByCompanyIdAndStatusOrderByIdDesc(users.getCompany().getId(), true);
            } else {
                balanceSummaries = ledgerRepository.findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
            }
        }catch (Exception e){
            System.out.println(e);
        }

        for (LedgerMaster balanceSummary : balanceSummaries) {
//            Long ledgerId = balanceSummary.getId();
            JsonObject jsonObject = new JsonObject();

            jsonObject.addProperty("id", balanceSummary.getId());
            jsonObject.addProperty("foundations_name", balanceSummary.getFoundations().getFoundationName());
            if (balanceSummary.getAssociateGroups() == null) {
                if (balanceSummary.getPrinciples() != null) {
                    jsonObject.addProperty("principle_name", balanceSummary.getPrinciples().getPrincipleName());
                }
                if (balanceSummary.getPrincipleGroups() != null) {
                    jsonObject.addProperty("subprinciple_name", balanceSummary.getPrincipleGroups().getGroupName());
                } else {
                    jsonObject.addProperty("subprinciple_name", "");
                }
            } else {
                if (balanceSummary.getAssociateGroups().getPrincipleGroups() != null) {
                    jsonObject.addProperty("principle_name", balanceSummary.getPrinciples().getPrincipleName());
                    jsonObject.addProperty("subprinciple_name", balanceSummary.getAssociateGroups().getAssociatesName());
                } else {
                    jsonObject.addProperty("principle_name", balanceSummary.getAssociateGroups().getAssociatesName());
                }
            }
            try {
                Double openingBalance = ledgerRepository.findOpeningBalance(balanceSummary.getId());
                sumCR = ledgerTransactionPostingsRepository.findsumCR(balanceSummary.getId());//-0.20
                sumDR = ledgerTransactionPostingsRepository.findsumDR(balanceSummary.getId());//-0.40
                closingBalance = openingBalance - sumDR + sumCR;//0-(-0.40)-0.20
            } catch (Exception e) {
                ledgerLogger.error("Exception:" + e.getMessage());
                e.printStackTrace();
            }
            jsonObject.addProperty("default_ledger", balanceSummary.getIsDefaultLedger());
            jsonObject.addProperty("ledger_form_parameter_slug", balanceSummary.getSlugName());
//            LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.findByLedgerMasterIdAndStatus(balanceSummary.getId(), true);
            if (balanceSummary.getFoundations().getId() == 1) {
                if (closingBalance > 0) {
                    jsonObject.addProperty("cr", df.format(Math.abs(closingBalance)));
                    jsonObject.addProperty("dr", df.format(0));
                } else {
                    jsonObject.addProperty("cr", df.format(0));
                    jsonObject.addProperty("dr", df.format(Math.abs(closingBalance)));
                }

            } else if (balanceSummary.getFoundations().getId() == 2) {
                if (closingBalance > 0) {
                    jsonObject.addProperty("cr", df.format(Math.abs(closingBalance)));
                    jsonObject.addProperty("dr", df.format(0));
                } else {
                    jsonObject.addProperty("cr", df.format(0));
                    jsonObject.addProperty("dr", df.format(Math.abs(closingBalance)));
                }

            } else if (balanceSummary.getFoundations().getId() == 3) {
                if (closingBalance > 0) {
                    jsonObject.addProperty("cr", df.format(Math.abs(closingBalance)));
                    jsonObject.addProperty("dr", df.format(0));
                } else {
                    jsonObject.addProperty("cr", df.format(0));
                    jsonObject.addProperty("dr", df.format(Math.abs(closingBalance)));
                }

            } else if (balanceSummary.getFoundations().getId() == 4) {
                if (closingBalance < 0) {
                    jsonObject.addProperty("cr", df.format(0));
                    jsonObject.addProperty("dr", df.format(Math.abs(closingBalance)));
                } else {
                    jsonObject.addProperty("cr", df.format(Math.abs(closingBalance)));
                    jsonObject.addProperty("dr", df.format(0));
                }
            }
            jsonObject.addProperty("ledger_name", balanceSummary.getLedgerName());

            result.add(jsonObject);
        }
        JsonObject json = new JsonObject();
        json.addProperty("company_name", users.getCompany().getCompanyName());
        json.addProperty("message", "success");
        json.addProperty("responseStatus", HttpStatus.OK.value());
        json.add("responseList", result);
        return json;
    }


/*    public String exportReport(HttpServletRequest request) throws IOException, JRException, URISyntaxException {

        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));

        List<LedgerMaster> ledgerMasters = new ArrayList<>();
        if (users.getBranch() != null) {
            ledgerMasters = ledgerRepository.findTop3ByCompanyIdAndBranchIdOrderByIdDesc(users.getCompany().getId(), users.getBranch().getId());
        } else {
            ledgerMasters = ledgerRepository.findTop3ByCompanyIdOrderByIdDesc(users.getCompany().getId());
        }

        */

    /*** Japser Reports ****//*

        //File file = ResourceUtils.getFile("classpath:ledger_report.jrxml");
        File file = ResourceUtils.getFile("classpath:ledger_blank.jrxml");

        File newfile = new File("resources/ledeger_blank.html");

        String absolutePath = file.getAbsolutePath();
        System.out.println("File Path:" + file.getAbsolutePath());
        try {
            JasperReport jasperReport = JasperCompileManager.compileReport(file.getAbsolutePath());
            JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(ledgerMasters);
            Map<String, Object> map = new HashMap<>();
            map.put("createdBy", users.getFullName());
            JasperPrint jasperPrint = JasperFillManager.fillReport(jasperReport, map, dataSource);
            printReport(jasperPrint, "CT-D150");

        } catch (Exception e) {
            e.printStackTrace();
            ledgerLogger.error("Exception in exportReport:" + e.getMessage());
            System.out.println("" + e.getMessage());
        }
        return "Report Generated ";
    }*/

    /*public void printReport(JasperPrint jasperPrint, String selectedPrinter) throws JRException {
        PrintRequestAttributeSet printRequestAttributeSet = new HashPrintRequestAttributeSet();
        printRequestAttributeSet.add(MediaSizeName.ISO_A4);
        if (jasperPrint.getOrientationValue() == net.sf.jasperreports.engine.type.OrientationEnum.LANDSCAPE) {
            printRequestAttributeSet.add(OrientationRequested.LANDSCAPE);
        } else {
            printRequestAttributeSet.add(OrientationRequested.PORTRAIT);
        }
        PrintServiceAttributeSet printServiceAttributeSet = new HashPrintServiceAttributeSet();
        printServiceAttributeSet.add(new PrinterName(selectedPrinter, null));

        JRPrintServiceExporter exporter = new JRPrintServiceExporter();
        SimplePrintServiceExporterConfiguration configuration = new SimplePrintServiceExporterConfiguration();
        configuration.setPrintRequestAttributeSet(printRequestAttributeSet);
        configuration.setPrintServiceAttributeSet(printServiceAttributeSet);
        configuration.setDisplayPageDialog(false);
        configuration.setDisplayPrintDialog(false);

        exporter.setExporterInput(new SimpleExporterInput(jasperPrint));
        exporter.setConfiguration(configuration);

        PrintService[] services = PrintServiceLookup.lookupPrintServices(null, null);
        PrintService selectedService = null;
        if (services.length != 0 || services != null) {
            for (PrintService service : services) {
                String existingPrinter = service.getName();
                if (existingPrinter.equals(selectedPrinter)) {
                    selectedService = service;
                    break;
                }
            }
        }
        if (selectedService != null) {
            exporter.exportReport();
        } else {
            System.out.println("You did not set the printer!");
        }
    }*/

    /* Sundry creditors overdue for bil by bill */
    public JsonObject getTotalAmountBillbyBill(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));

        List<LedgerTransactionDetails> list = new ArrayList<>();
        if (users.getBranch() != null) {
            list = transactionDetailsRepository.findByLedgerMasterIdAndCompanyIdAndBranchIdAndTransactionTypeId(Long.parseLong(request.getParameter("id")), users.getCompany().getId(), users.getBranch().getId(), 1L);
        } else {
            list = transactionDetailsRepository.findByLedgerMasterIdAndCompanyIdAndTransactionTypeId(Long.parseLong(request.getParameter("id")), users.getCompany().getId(), 1L);
        }
        JsonArray result = new JsonArray();

        for (LedgerTransactionDetails mList : list) {
            JsonObject jsonObject = new JsonObject();
            if (!mList.getPaymentStatus().equalsIgnoreCase("completed")) {
                jsonObject.addProperty("id", mList.getId());
                jsonObject.addProperty("ledger_id", mList.getLedgerMaster().getId());
                jsonObject.addProperty("transaction_id", mList.getTransactionId());
                if (mList.getPaymentStatus().equalsIgnoreCase("pending")) {
                    jsonObject.addProperty("amount", mList.getCredit());
                } else {
                    /*PaymentTransactionDetails paymentDetails = paymentTransactionDetailsRepo.
                            findTopByTransactionDetailsIdAndPaymentStatusOrderByIdDesc(mList.getId(), "partially_paid");
                    jsonObject.addProperty("amount", paymentDetails.getRemainingAmt());*/
                }
                result.add(jsonObject);
            }
        }
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "success");
            response.add("list", result);
        } else {
            response.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
            response.addProperty("message", "empty list");
            response.add("list", result);
        }
        return response;
    }

    public Object editLedgerMaster(HttpServletRequest request) {
        ResponseMessage responseMessage = new ResponseMessage();
        Long id = Long.parseLong(request.getParameter("id"));
        LedgerMaster ledgerMaster = repository.findByIdAndStatus(id, true);
        LedgerMaster mLedger = ledgerCreateUpdate(request, "edit", ledgerMaster);
        if (mLedger != null) {
            // insertIntoLedgerBalanceSummary(mLedger, "edit");
            responseMessage.setMessage("Ledger updated successfully");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        } else {
            responseMessage.setMessage("error");
            responseMessage.setResponseStatus(HttpStatus.FORBIDDEN.value());
        }
        return responseMessage;
    }

    /* get total balance of each sundry creditors for Payment Vouchers  */
    public JsonObject getTotalAmount(HttpServletRequest request, String key) {
        List<Object[]> list = new ArrayList<>();
        if (key.equalsIgnoreCase("sc")) {
            list = balanceSummaryRepository.calculate_total_amount(5L);
        } else if (key.equalsIgnoreCase("sd")) {
            list = balanceSummaryRepository.calculate_total_amount(1L);
        }
        JsonArray result = new JsonArray();
        for (int i = 0; i < list.size(); i++) {
            JsonObject jsonObject = new JsonObject();
            Object obj[] = list.get(i);
            jsonObject.addProperty("id", obj[0].toString());
            jsonObject.addProperty("amount", Math.abs(Double.parseDouble(obj[1].toString())));
            jsonObject.addProperty("name", obj[2].toString());
            LedgerMaster creditors = ledgerRepository.findByIdAndStatus(Long.parseLong(obj[0].toString()), true);
            jsonObject.addProperty("balancing_method", generateSlugs.getSlug(creditors.getBalancingMethod().getBalancingMethod()));
            jsonObject.addProperty("slug", creditors.getSlugName());
            if (key.equalsIgnoreCase("sc")) {
                if (Double.parseDouble(obj[1].toString()) > 0) jsonObject.addProperty("type", "DR");
                else jsonObject.addProperty("type", "CR");
            } else if (key.equalsIgnoreCase("sd")) {
                if (Double.parseDouble(obj[1].toString()) > 0) jsonObject.addProperty("type", "CR");
                else jsonObject.addProperty("type", "DR");
            }
            result.add(jsonObject);
        }
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "success");
            response.add("list", result);
        } else {
            response.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
            response.addProperty("message", "empty list");
            response.add("list", result);
        }
        return response;
    }

    public JsonObject getLedgersById(HttpServletRequest request) {
        JsonObject result = new JsonObject();
        JsonObject jsonObject = new JsonObject();
       /* Long id = Long.parseLong(request.getParameter("ledger_form_parameter_id"));
        String slug_name = request.getParameter("ledger_form_parameter_slug");*/
        try{
        LedgerMaster mLedger = repository.findByIdAndStatus(Long.parseLong(request.getParameter("id")), true);
        if (mLedger != null) {
            jsonObject.addProperty("id", mLedger.getId());
//            jsonObject.addProperty("associate_group_id", mLedger.getAssociateGroups().getId());
//            jsonObject.addProperty("drcr_type", mLedger.getOpeningBalType());4
            jsonObject.addProperty("default_ledger", mLedger.getIsDefaultLedger());
            jsonObject.addProperty("ledger_name", mLedger.getLedgerName());
            jsonObject.addProperty("is_private", mLedger.getIsPrivate());
            jsonObject.addProperty("supplier_code", mLedger.getLedgerCode() != null ? mLedger.getLedgerCode() : null);
            if (mLedger.getMailingName() != null) jsonObject.addProperty("mailing_name", mLedger.getMailingName());
            if (mLedger.getOpeningBalType() != null)
                jsonObject.addProperty("opening_bal_type", mLedger.getOpeningBalType());

            if (mLedger.getSalesRate() != null) {
                jsonObject.addProperty("sales_rate", mLedger.getSalesRate());
            }
//            if (mLedger.getColumnA() != null) {
//                jsonObject.addProperty("salesman", mLedger.getColumnA()); // columnA= salesman
//                jsonObject.addProperty("salesmanId", mLedger.getSalesmanId());
//            }
            if (mLedger.getRoute() != null) {
                jsonObject.addProperty("route", mLedger.getRoute());
            }
//            if (mLedger.getArea() != null) {
//                jsonObject.addProperty("area", mLedger.getArea());
//                jsonObject.addProperty("areaId", mLedger.getAreaId());
//            }
            if (mLedger.getOpeningBal() != null)
                jsonObject.addProperty("opening_bal", Math.abs(mLedger.getOpeningBal()));
            if (mLedger.getBalancingMethod() != null)
                jsonObject.addProperty("balancing_method", mLedger.getBalancingMethod().getId());
            if (mLedger.getAddress() != null) jsonObject.addProperty("address", mLedger.getAddress());
            jsonObject.addProperty("state", mLedger.getState() != null ? mLedger.getState().getId() : null);
            jsonObject.addProperty("country", mLedger.getCountry() != null ? mLedger.getCountry().getId() : null);
            if (mLedger.getPincode() != null) jsonObject.addProperty("pincode", mLedger.getPincode());
            if (mLedger.getCity() != null) jsonObject.addProperty("city", mLedger.getCity());

            if (mLedger.getEmail() != null) jsonObject.addProperty("email", mLedger.getEmail());
            if (mLedger.getMobile() != null) jsonObject.addProperty("mobile_no", mLedger.getMobile());
            if (mLedger.getTaxable() != null) jsonObject.addProperty("taxable", mLedger.getTaxable());
            if (mLedger.getTaxType() != null) jsonObject.addProperty("tax_type", mLedger.getTaxType());
            jsonObject.addProperty("under_prefix", mLedger.getUnderPrefix());
            jsonObject.addProperty("under_prefix_separator", mLedger.getUnderPrefix().split("#")[0]);
            jsonObject.addProperty("under_id", mLedger.getUnderPrefix().split("#")[1]);
            /* pune visit changes */
            jsonObject.addProperty("credit_days", mLedger.getCreditDays());
            jsonObject.addProperty("applicable_from", mLedger.getApplicableFrom());
            jsonObject.addProperty("sales_rate", mLedger.getSalesRate());
            jsonObject.addProperty("fssai", mLedger.getFoodLicenseNo() != null ? mLedger.getFoodLicenseNo() : "");
            jsonObject.addProperty("fssai_expiry", mLedger.getFssaiExpiry() != null ? mLedger.getFssaiExpiry().toString() : "");
            jsonObject.addProperty("drug_expiry", mLedger.getDrugExpiry() != null ? mLedger.getDrugExpiry().toString() : "");
            jsonObject.addProperty("drug_license_no", mLedger.getDrugLicenseNo() != null ? mLedger.getDrugLicenseNo().toString() : "");
            jsonObject.addProperty("tds", mLedger.getTds());
            jsonObject.addProperty("tcs", mLedger.getTcs());
            jsonObject.addProperty("tds_applicable_date", mLedger.getTdsApplicableDate() != null ? mLedger.getTdsApplicableDate().toString() : "");
            jsonObject.addProperty("tcs_applicable_date", mLedger.getTcsApplicableDate() != null ? mLedger.getTcsApplicableDate().toString() : "");
            jsonObject.addProperty("licenseNo", mLedger.getLicenseNo());
            jsonObject.addProperty("licenseExpiryDate", mLedger.getLicenseExpiry() != null ? mLedger.getLicenseExpiry().toString() : "");
            jsonObject.addProperty("manufacturingLicenseNo", mLedger.getManufacturingLicenseNo());
            jsonObject.addProperty("manufacturingLicenseExpiry", mLedger.getManufacturingLicenseExpiry() != null ? mLedger.getManufacturingLicenseExpiry().toString() : "");
            jsonObject.addProperty("gstTransferDate", mLedger.getGstTransferDate() != null ? mLedger.getGstTransferDate().toString() : "");
            jsonObject.addProperty("gstin", mLedger.getGstin());
            jsonObject.addProperty("place", mLedger.getPlace());
            jsonObject.addProperty("route", mLedger.getRoute());
            jsonObject.addProperty("district", mLedger.getDistrict());
            jsonObject.addProperty("landMark", mLedger.getLandMark());
            jsonObject.addProperty("businessType", mLedger.getBusinessType());
            jsonObject.addProperty("businessTrade", mLedger.getBusinessTrade());
            jsonObject.addProperty("creditNumBills", mLedger.getCreditNumBills());
            jsonObject.addProperty("creditBillValue", mLedger.getCreditBillValue());
            jsonObject.addProperty("lrBillDate", mLedger.getLrBillDate() != null ? mLedger.getLrBillDate().toString() : "");
            jsonObject.addProperty("creditBillDate", mLedger.getCreditBillDate() != null ? mLedger.getCreditBillDate().toString() : "");
            jsonObject.addProperty("anniversary", mLedger.getAnniversary() != null ? mLedger.getAnniversary().toString() : "");
            jsonObject.addProperty("dob", mLedger.getDob() != null ? mLedger.getDob().toString() : "");
            /* gst Details of Ledger */
            if (mLedger.getTaxable() != null && mLedger.getTaxable()) {
                JsonArray jsongstArray = new JsonArray();
                List<LedgerGstDetails> gstList = new ArrayList<>();
                gstList = ledgerGstDetailsRepository.findByLedgerMasterIdAndStatus(mLedger.getId(), true);
                if (gstList != null && gstList.size() > 0) {
                    for (LedgerGstDetails mList : gstList) {
                        JsonObject mObject = new JsonObject();
                        mObject.addProperty("id", mList.getId());
                        mObject.addProperty("gstin", mList.getGstin());
                        mObject.addProperty("dateOfRegistration", mList.getDateOfRegistration() != null ? mList.getDateOfRegistration().toString() : "");
                        mObject.addProperty("pancard", mList.getPanCard());
                        jsongstArray.add(mObject);
                    }
                }/*else{
                    JsonObject mObject = new JsonObject();
                    mObject.addProperty("id", "");
                    mObject.addProperty("gstin", mList.getGstin());
                    mObject.addProperty("dateOfRegistration", mList.getDateOfRegistration() != null ? mList.getDateOfRegistration().toString() : "");
                    mObject.addProperty("pancard", mList.getPanCard());
                    jsongstArray.add(mObject);
                }*/
                jsonObject.add("gstdetails", jsongstArray);
            }
            /* end of GST Details */

            /* Shipping Address Details */
            JsonArray jsonshippingArray = new JsonArray();
            List<LedgerShippingAddress> shippingList = new ArrayList<>();
            shippingList = ledgerShippingDetailsRepository.findByLedgerMasterIdAndStatus(mLedger.getId(), true);
            if (shippingList != null && shippingList.size() > 0) {
                for (LedgerShippingAddress mList : shippingList) {
                    JsonObject mObject = new JsonObject();
                    mObject.addProperty("id", mList.getId());
                    mObject.addProperty("district", mList.getDistrict());
                    mObject.addProperty("shipping_address", mList.getShippingAddress());
                    jsonshippingArray.add(mObject);
                }
            }
            jsonObject.add("shippingDetails", jsonshippingArray);
            /* End of Shipping Address Details */

            /* Billing Address Details */
            JsonArray jsonbillingArray = new JsonArray();
            List<LedgerBillingDetails> billingDetails = new ArrayList<>();
            billingDetails = ledgerBillingDetailsRepository.findByLedgerMasterIdAndStatus(mLedger.getId(), true);
            if (billingDetails != null && billingDetails.size() > 0) {
                for (LedgerBillingDetails mList : billingDetails) {
                    JsonObject mObject = new JsonObject();
                    mObject.addProperty("id", mList.getId());
                    mObject.addProperty("district", mList.getDistrict());
                    mObject.addProperty("billing_address", mList.getBillingAddress());
                    jsonbillingArray.add(mObject);
                }
            }
            jsonObject.add("billingDetails", jsonbillingArray);
            /* End of Billing Address Details */

            /* Bank Details */
            JsonArray jsonbankArray = new JsonArray();
            List<LedgerBankDetails> ledgerBankDetails = new ArrayList<>();
            ledgerBankDetails = ledgerbankDetailsRepository.findByLedgerMasterIdAndStatus(mLedger.getId(), true);
            if (ledgerBankDetails != null && ledgerBankDetails.size() > 0) {
                for (LedgerBankDetails mList : ledgerBankDetails) {
                    JsonObject mObject = new JsonObject();
                    mObject.addProperty("id", mList.getId());
                    mObject.addProperty("bank_name", mList.getBankName());
                    mObject.addProperty("bank_ifsc_code", mList.getIfsc());
                    mObject.addProperty("bank_account_no", mList.getAccountNo());
                    mObject.addProperty("bank_branch", mList.getBankBranch());
                    jsonbankArray.add(mObject);
                }
            }
            jsonObject.add("bankDetails", jsonbankArray);
            /* End of Billing Address Details */


            /* Deptartment Details */
            JsonArray jsondeptArray = new JsonArray();
            List<LedgerDeptDetails> deptDetails = new ArrayList<>();
            deptDetails = ledgerDeptDetailsRepository.findByLedgerMasterIdAndStatus(mLedger.getId(), true);
            if (deptDetails != null && deptDetails.size() > 0) {
                for (LedgerDeptDetails mList : deptDetails) {
                    JsonObject mObject = new JsonObject();
                    mObject.addProperty("id", mList.getId());
                    mObject.addProperty("dept", mList.getDept());
                    mObject.addProperty("contact_person", mList.getContactPerson());
                    mObject.addProperty("contact_no", mList.getContactNo() != null ? mList.getContactNo().toString() : "");
                    mObject.addProperty("email", mList.getEmail());
                    jsondeptArray.add(mObject);
                }
            }
            jsonObject.add("deptDetails", jsondeptArray);
            /* End of Department Details */

            if (mLedger.getRegistrationType() != null)
                jsonObject.addProperty("registration_type", mLedger.getRegistrationType());
            if (mLedger.getPancard() != null) jsonObject.addProperty("pancard_no", mLedger.getPancard());
            if (mLedger.getBankName() != null) jsonObject.addProperty("bank_name", mLedger.getBankName());
            if (mLedger.getAccountNumber() != null) jsonObject.addProperty("account_no", mLedger.getAccountNumber());
            if (mLedger.getIfsc() != null) jsonObject.addProperty("ifsc_code", mLedger.getIfsc());
            if (mLedger.getBankBranch() != null) jsonObject.addProperty("bank_branch", mLedger.getBankBranch());
            if (mLedger.getPrincipleGroups() != null) {
                jsonObject.addProperty("principle_id", mLedger.getPrinciples().getId());
                jsonObject.addProperty("principle_name", mLedger.getPrinciples().getPrincipleName());
                jsonObject.addProperty("ledger_form_parameter_id", mLedger.getPrincipleGroups().getLedgerFormParameter().getId());
                jsonObject.addProperty("ledger_form_parameter_slug", mLedger.getPrincipleGroups().getLedgerFormParameter().getSlugName());
                jsonObject.addProperty("sub_principle_id", mLedger.getPrincipleGroups().getId());
                jsonObject.addProperty("subprinciple_name", mLedger.getPrincipleGroups().getGroupName());
            } else {
                jsonObject.addProperty("principle_id", mLedger.getPrinciples().getId());
                jsonObject.addProperty("principle_name", mLedger.getPrinciples().getPrincipleName());
                jsonObject.addProperty("ledger_form_parameter_id", mLedger.getPrinciples().getLedgerFormParameter().getId());
                jsonObject.addProperty("ledger_form_parameter_slug", mLedger.getPrinciples().getLedgerFormParameter().getSlugName());
                jsonObject.addProperty("sub_principle_id", "");
                jsonObject.addProperty("subprinciple_name", "");
            }

            result.addProperty("message", "success");
            result.addProperty("responseStatus", HttpStatus.OK.value());
            result.add("response", jsonObject);
        } else {
            result.addProperty("message", "Not Found");
            result.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        }catch (Exception e){
            System.out.println("Exception " + e.getMessage());
            e.printStackTrace();
            result.addProperty("response","Failed to find Ledger");
            result.addProperty("responseStatus",HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return result;
    }


    /* public Object DTGetallledgers(Map<String, String> request, HttpServletRequest req) {
     *//*Users users = jwtRequestFilter.getUserDataFromToken(req.getHeader("Authorization").substring(7));
        Long outletId = users.getCompany().getId();
        Integer from = Integer.parseInt(request.get("from"));
        Integer to = Integer.parseInt(request.get("to"));
        String searchText = request.get("searchText");

        GenericDatatable genericDatatable = new GenericDatatable();
        List<LedgerBalanceSummaryDtView> ledgerBalanceSummaryDtViewList = new ArrayList<>();
        try {
            String query = "SELECT * FROM `ledger_balance_summary_dt_view` WHERE ledger_balance_summary_dt_view.outlet_id='" + outletId
                    + "' AND ledger_balance_summary_dt_view.status=1";

            if (!searchText.equalsIgnoreCase("")) {
                query = query + " AND (id LIKE '%" + searchText + "%' OR  ledger_name LIKE '%" + searchText + "%' OR group_name LIKE '%" +
                        searchText + "%' OR  principle_name LIKE '%" + searchText + "%' OR credit LIKE '%" +
                        searchText + "%' OR debit LIKE '%" +
                        searchText + "%' )";
            }

            String jsonToStr = request.get("sort");
            System.out.println(" sort " + jsonToStr);
            JsonObject jsonObject = new Gson().fromJson(jsonToStr, JsonObject.class);
            if (!jsonObject.get("colId").toString().equalsIgnoreCase("null") &&
                    jsonObject.get("colId").getAsString() != null) {
                System.out.println(" ORDER BY " + jsonObject.get("colId").getAsString());
                String sortBy = jsonObject.get("colId").getAsString();
                query = query + " ORDER BY " + sortBy;
                if (jsonObject.get("isAsc").getAsBoolean() == true) {
                    query = query + " ASC";
                } else {
                    query = query + " DESC";
                }
            } else {
                query = query + " ORDER BY ledger_name ASC";
            }
            String query1 = query;
            Integer endLimit = to - from;
            query = query + " LIMIT " + from + ", " + endLimit;
            System.out.println("query " + query);*//*

        //  Query q = entityManager.createNativeQuery(query, LedgerBalanceSummaryDtView.class);
        //  Query q1 = entityManager.createNativeQuery(query1, LedgerBalanceSummaryDtView.class);

        // ledgerBalanceSummaryDtViewList = q.getResultList();
        //   System.out.println("Limit total rows " + ledgerBalanceSummaryDtViewList.size());

        //   List<LedgerBalanceSummaryDtView> ledgerBalanceSummaryDtViewArrayList = new ArrayList<>();
       *//*     ledgerBalanceSummaryDtViewArrayList = q1.getResultList();
            System.out.println("total rows " + ledgerBalanceSummaryDtViewArrayList.size());

            genericDatatable.setRows(ledgerBalanceSummaryDtViewList);
            genericDatatable.setTotalRows(ledgerBalanceSummaryDtViewArrayList.size());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());

            genericDatatable.setRows(ledgerBalanceSummaryDtViewList);
            genericDatatable.setTotalRows(0);
        }
        return genericDatatable;*//*
    }*/

    /* get sundry creditors, sundry debtors,cash account and  bank accounts*/
    public Object getClientList(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        ClientsListDTO clientsListDTO = new ClientsListDTO();
        List<Object[]> sundryCreditors = new ArrayList<>();
        /* sundry Creditors List */
        if (users.getBranch() != null) {

            sundryCreditors = ledgerRepository.findSundryCreditorsByCompanyIdAndBranchId(users.getCompany().getId(), users.getBranch().getId());
        } else {
            sundryCreditors = ledgerRepository.findSundryCreditorsByCompanyId(users.getCompany().getId());
        }
        List<ClientDetails> clientDetails = new ArrayList<>();
        for (int i = 0; i < sundryCreditors.size(); i++) {
            ClientDetails mDetails = new ClientDetails();
            Object obj[] = sundryCreditors.get(i);
            mDetails.setId(Long.parseLong(obj[0].toString()));
            mDetails.setLedger_name((String) obj[1]);
            mDetails.setLedger_code((String) obj[2]);
            mDetails.setStateCode((String) obj[3]);
            clientDetails.add(mDetails);
        }
        /* end of Sundry creditors List */

        /* sundry Debtors List */
        List<Object[]> sundryDebtors = new ArrayList<>();
        if (users.getBranch() != null) {
            sundryDebtors = ledgerRepository.findSundryDebtorsByCompanyIdAndBranchId(users.getCompany().getId(), users.getBranch().getId());
        } else {
            sundryDebtors = ledgerRepository.findSundryDebtorsByCompanyId(users.getCompany().getId());
        }
        for (int i = 0; i < sundryDebtors.size(); i++) {
            ClientDetails mDetails = new ClientDetails();
            Object obj[] = sundryDebtors.get(i);
            mDetails.setId(Long.parseLong(obj[0].toString()));
            mDetails.setLedger_name((String) obj[1]);
            mDetails.setLedger_code((String) obj[2]);
            mDetails.setStateCode((String) obj[3]);
            clientDetails.add(mDetails);
        }
        /* end of Sundry debtors List */

        /* Cash-in Hand List */
        List<Object[]> cashInHands = new ArrayList<>();
        if (users.getBranch() != null) {
            cashInHands = ledgerRepository.findCashInHandByCompanyIdAndBranch(users.getCompany().getId(), users.getBranch().getId());
        } else {
            cashInHands = ledgerRepository.findCashInHandByCompanyId(users.getCompany().getId());
        }
        for (int i = 0; i < cashInHands.size(); i++) {
            ClientDetails mDetails = new ClientDetails();
            Object obj[] = cashInHands.get(i);
            mDetails.setId(Long.parseLong(obj[0].toString()));
            mDetails.setLedger_name((String) obj[1]);
            mDetails.setLedger_code((String) obj[2]);
            mDetails.setStateCode((String) obj[3]);
            clientDetails.add(mDetails);
        }
        /* end of Cash in Hand List */

        /* Bank Accounts List */
        List<Object[]> bankAccounts = new ArrayList<>();
        if (users.getBranch() != null) {
            bankAccounts = ledgerRepository.findBankAccountsByCompanyIdAndBranch(users.getCompany().getId(), users.getBranch().getId());
        } else {
            bankAccounts = ledgerRepository.findBankAccountsByCompanyId(users.getCompany().getId());
        }
        for (int i = 0; i < bankAccounts.size(); i++) {
            ClientDetails mDetails = new ClientDetails();
            Object obj[] = bankAccounts.get(i);
            mDetails.setId(Long.parseLong(obj[0].toString()));
            mDetails.setLedger_name((String) obj[1]);
            mDetails.setLedger_code((String) obj[2]);
            mDetails.setStateCode((String) obj[3]);
            clientDetails.add(mDetails);
        }
        /* end of Bank accounts List */
        if (clientDetails.size() > 0) {
            clientsListDTO.setMessage("success");
            clientsListDTO.setResponseStatus(HttpStatus.OK.value());
            clientsListDTO.setList(clientDetails);
        } else {
            clientsListDTO.setMessage("empty list");
            clientsListDTO.setResponseStatus(HttpStatus.OK.value());
            clientsListDTO.setList(clientDetails);
        }
        return clientsListDTO;
    }

    /* Get Cash-In-Hand and Bank Account Ledger from ledger balancer summary   */
    public JsonObject getCashAcBankAccount(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        LedgerMaster ledgerMaster = null;
        if (users.getBranch() != null) {

            ledgerMaster = ledgerRepository.findLedgerIdAndBranchIdAndName(users.getCompany().getId(), users.getBranch().getId());
        } else {
            ledgerMaster = ledgerRepository.findLedgerIdAndName(users.getCompany().getId());
        }
        LedgerBalanceSummary cashList = balanceSummaryRepository.findByLedgerMasterId(ledgerMaster.getId());
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("id", cashList.getId());
        jsonObject.addProperty("name", cashList.getLedgerMaster().getLedgerName());
        jsonObject.addProperty("slug", generateSlugs.getSlug(cashList.getPrincipleGroups().getGroupName()));
        if (cashList.getDebit() != 0.0) jsonObject.addProperty("amount", cashList.getDebit());
        else jsonObject.addProperty("amount", cashList.getCredit());
        result.add(jsonObject);
        List<LedgerBalanceSummary> bankList = balanceSummaryRepository.findByPrincipleGroupsId(2L);
        for (LedgerBalanceSummary mList : bankList) {
            JsonObject jsonObject_ = new JsonObject();
            jsonObject_.addProperty("id", mList.getId());
            jsonObject_.addProperty("name", mList.getLedgerMaster().getLedgerName());
            jsonObject_.addProperty("slug", generateSlugs.getSlug(mList.getPrincipleGroups().getGroupName()));
            if (cashList.getDebit() != 0.0) jsonObject.addProperty("amount", mList.getDebit());
            else jsonObject.addProperty("amount", mList.getCredit());
            result.add(jsonObject_);
        }
        JsonObject response = new JsonObject();
        if (result.size() > 0) {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "success");
            response.add("list", result);
        } else {
            response.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
            response.addProperty("message", "empty list");
            response.add("list", result);
        }
        return response;
    }

    public JsonObject getSundryDebtorsById(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        JsonObject result = new JsonObject();

        LedgerMaster sundryDebtors = ledgerRepository.findByIdAndStatus(Long.parseLong(request.getParameter("sundry_debtors_id")), true);
        if (sundryDebtors != null) {
            result.addProperty("id", sundryDebtors.getId());
            result.addProperty("sundry_debtors_name", sundryDebtors.getLedgerName());
            result.addProperty("mobile", sundryDebtors.getMobile());
            result.addProperty("address", sundryDebtors.getAddress());
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "success");
            response.add("data", result);
        } else {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "empty data");
            response.add("data", result);
        }

        return response;
    }

    public JsonObject getSundryCreditorsById(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        JsonObject response = new JsonObject();
        JsonObject result = new JsonObject();
        System.out.println("Sundry Creditor Id:" + request.getParameter("sundry_creditors_id"));
        LedgerMaster sundryCreditor = ledgerRepository.findByIdAndStatus(Long.parseLong(request.getParameter("sundry_creditors_id")), true);
        if (sundryCreditor != null) {
            result.addProperty("id", sundryCreditor.getId());
            result.addProperty("sundry_creditor_name", sundryCreditor.getLedgerName());
            result.addProperty("mobile", sundryCreditor.getMobile());
            result.addProperty("address", sundryCreditor.getAddress());
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "success");
            response.add("data", result);
        } else {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "success");
            response.add("data", result);
        }
        return response;
    }

    public JsonObject getGstDetails(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray result = new JsonArray();
        List<LedgerGstDetails> gstDetails = new ArrayList<>();
        Long ledgerId = Long.valueOf(request.getParameter("ledger_id"));
        gstDetails = ledgerGstDetailsRepository.findByLedgerMasterIdAndStatus(ledgerId, true);
        if (gstDetails != null && gstDetails.size() > 0) {
            for (LedgerGstDetails mDetails : gstDetails) {
                JsonObject mObject = new JsonObject();
                mObject.addProperty("id", mDetails.getId());
                mObject.addProperty("gstNo", mDetails.getGstin());
                mObject.addProperty("dateOfRegistration", mDetails.getDateOfRegistration() != null ? mDetails.getDateOfRegistration().toString() : "");
                mObject.addProperty("pancard", mDetails.getPanCard());
                result.add(mObject);
            }
        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("list", result);
        return response;
    }

    public JsonObject getShippingDetails(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray result = new JsonArray();
        List<LedgerShippingAddress> shippingDetails = new ArrayList<>();
        Long ledgerId = Long.valueOf(request.getParameter("ledger_id"));
        shippingDetails = ledgerShippingDetailsRepository.findByLedgerMasterIdAndStatus(ledgerId, true);
        if (shippingDetails != null && shippingDetails.size() > 0) {
            for (LedgerShippingAddress mDetails : shippingDetails) {
                JsonObject mObject = new JsonObject();
                mObject.addProperty("id", mDetails.getId());
                mObject.addProperty("district", mDetails.getDistrict());
                mObject.addProperty("shipping_address", mDetails.getShippingAddress());
                result.add(mObject);
            }
        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("list", result);
        return response;
    }

    public JsonObject getDeptDetails(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray result = new JsonArray();
        List<LedgerDeptDetails> deptDetails = new ArrayList<>();
        Long ledgerId = Long.valueOf(request.getParameter("ledger_id"));
        deptDetails = ledgerDeptDetailsRepository.findByLedgerMasterIdAndStatus(ledgerId, true);
        if (deptDetails != null && deptDetails.size() > 0) {
            for (LedgerDeptDetails mDetails : deptDetails) {
                JsonObject mObject = new JsonObject();
                mObject.addProperty("id", mDetails.getId());
                mObject.addProperty("department", mDetails.getDept());
                mObject.addProperty("contact_no", mDetails.getContactNo());
                mObject.addProperty("contact_person", mDetails.getContactPerson());
                mObject.addProperty("email", mDetails.getEmail());
                result.add(mObject);
            }
        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("list", result);
        return response;
    }

    public JsonObject getBillingDetails(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonArray result = new JsonArray();
        List<LedgerBillingDetails> billDetails = new ArrayList<>();
        Long ledgerId = Long.valueOf(request.getParameter("ledger_id"));
        billDetails = ledgerBillingDetailsRepository.findByLedgerMasterIdAndStatus(ledgerId, true);
        if (billDetails != null && billDetails.size() > 0) {
            for (LedgerBillingDetails mDetails : billDetails) {
                JsonObject mObject = new JsonObject();
                mObject.addProperty("id", mDetails.getId());
                mObject.addProperty("billing_address", mDetails.getBillingAddress());
                mObject.addProperty("district", mDetails.getDistrict());
                result.add(mObject);
            }
        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("list", result);
        return response;
    }

    public JsonObject getCounterCustomer(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        LedgerMaster sundryDebtors = null;
        JsonObject object = new JsonObject();
        if (users.getBranch() != null) {
            sundryDebtors = ledgerRepository.findByLedgerNameIgnoreCaseAndCompanyIdAndBranchIdAndStatus("Counter Customer", users.getCompany().getId(), users.getBranch().getId(), true);
        } else {
            sundryDebtors = ledgerRepository.findByLedgerNameIgnoreCaseAndCompanyIdAndStatusAndBranchIsNull("Counter Customer", users.getCompany().getId(), true);
        }
        JsonArray result = new JsonArray();
        JsonObject response = new JsonObject();
        if (sundryDebtors != null) {
            object.addProperty("name", sundryDebtors.getLedgerName());
            object.addProperty("id", sundryDebtors.getId());
        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("data", object);
        return response;
    }

    public Object validateLedgerMaster(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Long branchId = null;
        Long pgroupId = null;
        String ledgerCodeId = null;
        ResponseMessage responseMessage = new ResponseMessage();
        LedgerMaster lMaster = null;
        LedgerMaster lMaster1 = null;
        Map<String, String[]> paramMap = request.getParameterMap();
        if (users.getBranch() != null) branchId = users.getBranch().getId();
          /*  lMaster = ledgerRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCaseAndStatus(users.getCompany().getId(), users.getBranch().getId(), request.getParameter("ledger_name"), true);
        } else {
            lMaster = ledgerRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndStatus(users.getCompany().getId(), request.getParameter("ledger_name"), true);
        }*/
        if (paramMap.containsKey("principle_group_id"))
            pgroupId = Long.parseLong(request.getParameter("principle_group_id"));
        if (paramMap.containsKey("ledger_code")) {
            ledgerCodeId = request.getParameter("ledger_code");
        }
        if (pgroupId != null) {
//            lMaster = ledgerRepository.findDuplicateWithName(users.getCompany().getId(), branchId, Long.parseLong(request.getParameter("principle_id")), pgroupId, request.getParameter("ledger_name").toLowerCase(), true);
//            lMaster = ledgerRepository.findDuplicateWithCode(users.getCompany().getId(), branchId, Long.parseLong(request.getParameter("principle_id")), pgroupId, request.getParameter("ledger_code").toLowerCase(), true);
            lMaster = ledgerRepository.findDuplicateWithName(users.getCompany().getId(), branchId, Long.parseLong(request.getParameter("principle_id")), pgroupId, request.getParameter("ledger_name").toLowerCase(), true);
            lMaster1 = ledgerRepository.findDuplicateWithCode(users.getCompany().getId(), branchId, Long.parseLong(request.getParameter("principle_id")), pgroupId, ledgerCodeId, true);
        } else {
            lMaster = ledgerRepository.findDuplicate(users.getCompany().getId(), branchId, Long.parseLong(request.getParameter("principle_id")), request.getParameter("ledger_name").toLowerCase(), true);
        }
        if (lMaster != null || lMaster1 != null) {
            responseMessage.setMessage("Duplicate ledger");
            responseMessage.setResponseStatus(HttpStatus.CONFLICT.value());
        } else {
            responseMessage.setMessage("New Ledger");
            responseMessage.setResponseStatus(HttpStatus.OK.value());
        }
        return responseMessage;
    }

    public Object getGSTListByLedgerId(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        try {
            Long ledgerId = Long.valueOf(request.getParameter("ledgerId"));
            List<LedgerGstDetails> ledgerGstDetails = ledgerGstDetailsRepository.findByLedgerMasterIdAndStatus(
                    ledgerId, true);

            JsonArray gstArray = new JsonArray();
            for (LedgerGstDetails ledgerGstDetails1 : ledgerGstDetails) {
                JsonObject gstObject = new JsonObject();
                gstObject.addProperty("id", ledgerGstDetails1.getId());
                gstObject.addProperty("gstNumber", ledgerGstDetails1.getGstin());
                gstObject.addProperty("dateOfRegistration", ledgerGstDetails1.getDateOfRegistration().toString());
                gstObject.addProperty("panNumber", ledgerGstDetails1.getPanCard());

                gstArray.add(gstObject);
            }

            response.add("response", gstArray);
            response.addProperty("responseStatus", HttpStatus.OK.value());

            return response;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());

            response.addProperty("message", "Failed to get gst data");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public Object checkLedgerDrugAndFssaiExpiryByLedgerId(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        try {
            Long ledgerId = Long.valueOf(request.getParameter("ledgerId"));
            LocalDate currentDate = LocalDate.now();

            LedgerMaster ledgerMaster = ledgerRepository.findByIdAndStatus(ledgerId, true);
            if (ledgerMaster != null) {

                System.out.println("current date is okay");
                response.addProperty("response", true);
                response.addProperty("responseStatus", HttpStatus.OK.value());

                String message = "";

                if (ledgerMaster.getFssaiExpiry() != null && currentDate.compareTo(ledgerMaster.getFssaiExpiry()) > 0) {
                    System.out.println("current date is greater than fssai date");

                    message = "Fssai licence";
                    response.addProperty("message", "Fssai licence expired");
                    response.addProperty("response", false);
                    response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
                }
                if (ledgerMaster.getDrugExpiry() != null && currentDate.compareTo(ledgerMaster.getDrugExpiry()) > 0) {
                    System.out.println("current date is greater than drug expiry date");

                    if (!message.equalsIgnoreCase("")) message = message + " & ";
                    message = message + "Drug licence";
                    response.addProperty("response", false);
                    response.addProperty("responseStatus", HttpStatus.NOT_FOUND.value());
                }
                response.addProperty("message", message);
            }
            return response;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            response.addProperty("response", false);
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    public JsonObject ledgerDelete(HttpServletRequest request) {
        JsonObject jsonObject = new JsonObject();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        Long count = 0L;
        try {
            LedgerMaster ledgerMaster = ledgerRepository.findByIdAndIsDefaultLedgerAndStatus(Long.parseLong(request.getParameter("id")), false, true);
            if (ledgerMaster != null) {
                count = ledgerTransactionPostingsRepository.findByLedgerTranx(ledgerMaster.getId(), true);

                if (count == 0) {
                    ledgerMaster.setStatus(false);
                    ledgerRepository.save(ledgerMaster);
                    jsonObject.addProperty("message", "ledger deleted successfully");
                    jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
                } else {
                    jsonObject.addProperty("message", "Not allowed to delete ledger,this ledger is used in transactions");
                    jsonObject.addProperty("responseStatus", HttpStatus.CONFLICT.value());
                }
            } else {
                jsonObject.addProperty("message", "Not allowed to delete default ledger");
                jsonObject.addProperty("responseStatus", HttpStatus.CONFLICT.value());
            }
        } catch (Exception e) {
//            purInvoiceLogger.error("Error in purchaseDelete()->" + e.getMessage());
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
        }
        return jsonObject;
    }

    public Object ledgerTransactionsList(HttpServletRequest request) {
        Double sumCR = 0.0;
        Double sumDR = 0.0;
        Double closingBalance = 0.0;
        JsonObject response = new JsonObject();
        JsonArray result = new JsonArray();
        List<LedgerMaster> ledgerMasters = new ArrayList<>();
        String searchKey = request.getParameter("search");
        Users users = null;
        users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));

        String query = " SELECT * FROM `ledger_master_tbl` WHERE company_id=" + users.getCompany().getId() + " AND" + " (principle_groups_id=1 OR principle_groups_id=5) AND status=1";

        if (users.getBranch() != null) {
            query = query + " AND branch_id=" + users.getBranch().getId();
        }
        if (!searchKey.equalsIgnoreCase("")) {
            query = query + " AND (ledger_code LIKE '%" + searchKey + "%' OR ledger_name LIKE '%" + searchKey + "%' OR city LIKE '%" + searchKey + "%' OR mobile LIKE '%" + searchKey + "%')";
        }
        System.out.println("query " + query);
        Query q = entityManager.createNativeQuery(query, LedgerMaster.class);
        ledgerMasters = q.getResultList();

        /*if (searchKey.equalsIgnoreCase("")) {
            if (users.getBranch() != null) {
                ledgerMasters = ledgerRepository.findBySCSDWithBranch(users.getCompany().getId(), users.getBranch().getId(),
                        1L, 5L, true);
            } else {
                ledgerMasters = ledgerRepository.findBySCSD(users.getCompany().getId(), 1L, 5L, true);
            }
        } else {
            if (users.getBranch() != null)
                ledgerMasters = ledgerRepository.findSearchKeyWithBranch(users.getCompany().getId(),
                        users.getBranch().getId(), searchKey, 1L, 5L, true);
            else
                ledgerMasters = ledgerRepository.findSearchKey(users.getCompany().getId(), searchKey, 1L, 5L, true);
        }*/
        System.out.println("ledgerMasters size " + ledgerMasters.size());
        if (ledgerMasters != null && ledgerMasters.size() > 0) {
            for (LedgerMaster mDetails : ledgerMasters) {
                JsonObject mObject = new JsonObject();
                mObject.addProperty("id", mDetails.getId());
                mObject.addProperty("code", mDetails.getLedgerCode() != null ? mDetails.getLedgerCode() : "");
                mObject.addProperty("ledger_name", mDetails.getLedgerName());
                mObject.addProperty("ledger_code", mDetails.getLedgerCode() != null ? mDetails.getLedgerCode() : "");
                mObject.addProperty("city", mDetails.getCity() != null ? mDetails.getCity() : "");
                mObject.addProperty("contact_number", mDetails.getMobile() != null ? mDetails.getMobile().toString() : "");
//                mObject.addProperty("sales_man", mDetails.getColumnA() != "" ? mDetails.getColumnA() : "");
                mObject.addProperty("stateCode", mDetails.getStateCode() != "" ? mDetails.getStateCode() : "");
                mObject.addProperty("salesRate", mDetails.getSalesRate() != null ? mDetails.getSalesRate() : 1);
                mObject.addProperty("balancingMethod", mDetails.getBalancingMethod() != null ? (mDetails.getBalancingMethod().getBalancingMethod() != null ? mDetails.getBalancingMethod().getBalancingMethod() : "") : "");
                if (mDetails.getUniqueCode().equalsIgnoreCase("SUCR")) mObject.addProperty("type", "SC");
                if (mDetails.getUniqueCode().equalsIgnoreCase("SUDR")) mObject.addProperty("type", "SD");
                mObject.addProperty("isFirstDiscountPerCalculate", mDetails.getIsFirstDiscountPerCalculate() != null ? mDetails.getIsFirstDiscountPerCalculate() : false);
                mObject.addProperty("takeDiscountAmountInLumpsum", mDetails.getTakeDiscountAmountInLumpsum() != null ? mDetails.getTakeDiscountAmountInLumpsum() : false);

                Double balance = balanceSummaryRepository.findBalance(mDetails.getId());
                if (balance != null) {
                    if (balance > 0) {
                        response.addProperty("ledger_balance", balance);
                        response.addProperty("ledger_balance_type", "CR");
                    } else {
                        response.addProperty("ledger_balance", Math.abs(balance));
                        response.addProperty("ledger_balance_type", "DR");
                    }
                }

                try {
                    Double openingBalance = ledgerRepository.findOpeningBalance(mDetails.getId());
                    sumCR = ledgerTransactionPostingsRepository.findsumCR(mDetails.getId());//-0.20
                    sumDR = ledgerTransactionPostingsRepository.findsumDR(mDetails.getId());//-0.40
                    closingBalance = openingBalance - sumDR + sumCR;//0-(-0.40)-0.20
                } catch (Exception e) {
                    ledgerLogger.error("Exception:" + e.getMessage());
                    e.printStackTrace();
                }
                mObject.addProperty("current_balance", Math.abs(closingBalance));
                if (closingBalance == 0)
                    mObject.addProperty("balance_type", mDetails.getOpeningBalType().toUpperCase());
                else {
                    if (mDetails.getFoundations().getId() == 1L) { //Assets
                        mObject.addProperty("balance_type", closingBalance < 0 ? "DR" : "CR");
                    } else if (mDetails.getFoundations().getId() == 2L) { //Liabilities
                        mObject.addProperty("balance_type", closingBalance > 0 ? "CR" : "DR");
                    } else if (mDetails.getFoundations().getId() == 3L) {//Inconme
                        mObject.addProperty("balance_type", closingBalance > 0 ? "CR" : "DR");
                    } else if (mDetails.getFoundations().getId() == 4L) {//Expenses
                        mObject.addProperty("balance_type", closingBalance < 0 ? "DR" : "CR");
                    }
                }

                List<LedgerGstDetails> gstDetails = new ArrayList<>();
                gstDetails = ledgerGstDetailsRepository.findByLedgerMasterIdAndStatus(mDetails.getId(), true);
                JsonArray gstArray = new JsonArray();
                if (gstDetails != null && gstDetails.size() > 0) {
                    for (LedgerGstDetails mGstDetails : gstDetails) {
                        JsonObject mGstObject = new JsonObject();
                        mGstObject.addProperty("id", mGstDetails.getId());
                        mGstObject.addProperty("gstNo", mGstDetails.getGstin());
                        mGstObject.addProperty("state", mGstDetails.getStateCode() != null ? mGstDetails.getStateCode() : "");
                        gstArray.add(mGstObject);
                    }
                }
                mObject.add("gstDetails", gstArray);
                result.add(mObject);
            }
        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("list", result);
        return response;
    }

    public Object ledgerVouchersList(HttpServletRequest request) {
        Double sumCR = 0.0;
        Double sumDR = 0.0;
        Double closingBalance = 0.0;
        JsonObject response = new JsonObject();
        JsonArray result = new JsonArray();
        List<LedgerMaster> ledgerMasters = new ArrayList<>();
        String searchKey = request.getParameter("search");
        Users users = null;
        users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));

        String query = " SELECT * FROM `ledger_master_tbl` WHERE principle_groups_id NOT IN(1,5) OR principle_groups_id IS NULL AND status = 1";

        if (users.getBranch() != null) {
            query = query + " AND branch_id=" + users.getBranch().getId();
        }
        if (!searchKey.equalsIgnoreCase("")) {
            query = query + " AND (ledger_code LIKE '%" + searchKey + "%' OR ledger_name LIKE '%" + searchKey + "%' OR city LIKE '%" + searchKey + "%' OR mobile LIKE '%" + searchKey + "%')";
        }
        System.out.println("query " + query);
        Query q = entityManager.createNativeQuery(query, LedgerMaster.class);
        ledgerMasters = q.getResultList();

        /*if (searchKey.equalsIgnoreCase("")) {
            if (users.getBranch() != null) {
                ledgerMasters = ledgerRepository.findBySCSDWithBranch(users.getCompany().getId(), users.getBranch().getId(),
                        1L, 5L, true);
            } else {
                ledgerMasters = ledgerRepository.findBySCSD(users.getCompany().getId(), 1L, 5L, true);
            }
        } else {
            if (users.getBranch() != null)
                ledgerMasters = ledgerRepository.findSearchKeyWithBranch(users.getCompany().getId(),
                        users.getBranch().getId(), searchKey, 1L, 5L, true);
            else
                ledgerMasters = ledgerRepository.findSearchKey(users.getCompany().getId(), searchKey, 1L, 5L, true);
        }*/
        System.out.println("ledgerMasters size " + ledgerMasters.size());
        if (ledgerMasters != null && ledgerMasters.size() > 0) {
            for (LedgerMaster mDetails : ledgerMasters) {
                JsonObject mObject = new JsonObject();
                mObject.addProperty("id", mDetails.getId());
                mObject.addProperty("code", mDetails.getLedgerCode() != null ? mDetails.getLedgerCode() : "");
                mObject.addProperty("ledger_name", mDetails.getLedgerName());
                mObject.addProperty("ledger_code", mDetails.getLedgerCode() != null ? mDetails.getLedgerCode() : "");
                mObject.addProperty("city", mDetails.getCity() != null ? mDetails.getCity() : "");
                mObject.addProperty("contact_number", mDetails.getMobile() != null ? mDetails.getMobile().toString() : "");
//                mObject.addProperty("sales_man", mDetails.getColumnA() != "" ? mDetails.getColumnA() : "");
                mObject.addProperty("stateCode", mDetails.getStateCode() != "" ? mDetails.getStateCode() : "");
                mObject.addProperty("salesRate", mDetails.getSalesRate() != null ? mDetails.getSalesRate() : 1);
                mObject.addProperty("isFirstDiscountPerCalculate", mDetails.getIsFirstDiscountPerCalculate() != null ? mDetails.getIsFirstDiscountPerCalculate() : false);
                mObject.addProperty("takeDiscountAmountInLumpsum", mDetails.getTakeDiscountAmountInLumpsum() != null ? mDetails.getTakeDiscountAmountInLumpsum() : false);

                Double balance = balanceSummaryRepository.findBalance(mDetails.getId());
                if (balance != null) {
                    if (balance > 0) {
                        response.addProperty("ledger_balance", balance);
                        response.addProperty("ledger_balance_type", "CR");
                    } else {
                        response.addProperty("ledger_balance", Math.abs(balance));
                        response.addProperty("ledger_balance_type", "DR");
                    }
                }

                try {
                    Double openingBalance = ledgerRepository.findOpeningBalance(mDetails.getId());
                    sumCR = ledgerTransactionPostingsRepository.findsumCR(mDetails.getId());//-0.20
                    sumDR = ledgerTransactionPostingsRepository.findsumDR(mDetails.getId());//-0.40
                    closingBalance = openingBalance - sumDR + sumCR;//0-(-0.40)-0.20
                } catch (Exception e) {
                    ledgerLogger.error("Exception:" + e.getMessage());
                    e.printStackTrace();
                }
                mObject.addProperty("current_balance", Math.abs(closingBalance));
                if (closingBalance == 0) mObject.addProperty("balance_type", mDetails.getOpeningBalType());
                else {
                    if (mDetails.getFoundations().getId() == 1L) { //Assets
                        mObject.addProperty("balance_type", closingBalance < 0 ? "DR" : "CR");
                    } else if (mDetails.getFoundations().getId() == 2L) { //Liabilities
                        mObject.addProperty("balance_type", closingBalance > 0 ? "CR" : "DR");
                    } else if (mDetails.getFoundations().getId() == 3L) {//Inconme
                        mObject.addProperty("balance_type", closingBalance > 0 ? "CR" : "DR");
                    } else if (mDetails.getFoundations().getId() == 4L) {//Expenses
                        mObject.addProperty("balance_type", closingBalance < 0 ? "DR" : "CR");
                    }
                }

                List<LedgerGstDetails> gstDetails = new ArrayList<>();
                gstDetails = ledgerGstDetailsRepository.findByLedgerMasterIdAndStatus(mDetails.getId(), true);
                JsonArray gstArray = new JsonArray();
                if (gstDetails != null && gstDetails.size() > 0) {
                    for (LedgerGstDetails mGstDetails : gstDetails) {
                        JsonObject mGstObject = new JsonObject();
                        mGstObject.addProperty("id", mGstDetails.getId());
                        mGstObject.addProperty("gstNo", mGstDetails.getGstin());
                        mGstObject.addProperty("state", mGstDetails.getStateCode() != null ? mGstDetails.getStateCode() : "");
                        gstArray.add(mGstObject);
                    }
                }
                mObject.add("gstDetails", gstArray);
                result.add(mObject);
            }
        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("list", result);
        return response;
    }

    public Object ledgerTransactionsDetails(HttpServletRequest request) {
        JsonObject response = new JsonObject();
        JsonObject mObject = new JsonObject();
        Long ledgerId = Long.parseLong(request.getParameter("ledger_id"));
        LedgerMaster ledgerMasters = null;
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        if (users.getBranch() != null) {
            ledgerMasters = ledgerRepository.findByCompanyIdAndBranchIdAndStatusAndId(users.getCompany().getId(), users.getBranch().getId(), true, ledgerId);
        } else {
            ledgerMasters = ledgerRepository.findByCompanyIdAndStatusAndIdAndBranchIsNull(users.getCompany().getId(), true, ledgerId);
        }
        if (ledgerMasters != null) {
            mObject.addProperty("license_number", ledgerMasters.getLicenseNo());
            mObject.addProperty("fssai_number", ledgerMasters.getFoodLicenseNo());
            mObject.addProperty("area", ledgerMasters.getArea());
            mObject.addProperty("route", ledgerMasters.getRoute());
            mObject.addProperty("credit_days", ledgerMasters.getCreditDays());
            /***** getting GST Details ****/
            List<LedgerGstDetails> gstDetails = new ArrayList<>();
            gstDetails = ledgerGstDetailsRepository.findByLedgerMasterIdAndStatus(ledgerId, true);
            if (gstDetails != null && gstDetails.size() > 0) {
                mObject.addProperty("gst_number", gstDetails.get(0).getGstin());
            } else {
                mObject.addProperty("gst_number", "");
            }
            /***** getting Bank Details ****/
            List<LedgerBankDetails> bankDetails = new ArrayList<>();
            bankDetails = ledgerbankDetailsRepository.findByLedgerMasterIdAndStatus(ledgerId, true);
            if (bankDetails != null && bankDetails.size() > 0) {
                mObject.addProperty("bank_name", bankDetails.get(0).getBankName());
                mObject.addProperty("account_number", bankDetails.get(0).getAccountNo());
            } else {
                mObject.addProperty("bank_name", "");
                mObject.addProperty("account_number", "");
            }
            /***** getting Contact Person Details ****/
            List<LedgerDeptDetails> ledgerDeptDetails = new ArrayList<>();
            ledgerDeptDetails = ledgerDeptDetailsRepository.findByLedgerMasterIdAndStatus(ledgerId, true);
            if (ledgerDeptDetails != null && ledgerDeptDetails.size() > 0) {
                mObject.addProperty("contact_name", ledgerDeptDetails.get(0).getContactPerson());
            } else {
                mObject.addProperty("contact_name", "");
            }
        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("result", mObject);
        return response;
    }

    public JsonObject getPayrollLedgers(HttpServletRequest request) {
        JsonObject response = new JsonObject();

        JsonArray result = new JsonArray();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<LedgerMaster> list = ledgerRepository.findByCompanyIdAndBranchIdAndStatus(users.getCompany().getId(),users.getBranch().getId(), true);
        for(LedgerMaster mLedger: list){
            JsonObject mObject = new JsonObject();
            if(mLedger.getLedgerName().equals("Basic Salary A/c")){
                mObject.addProperty("headname",mLedger.getLedgerName());
                mObject.addProperty("ledger_id",mLedger.getId());
                result.add(mObject);
            } else if(mLedger.getLedgerName().equals("Special allowance A/c")){
                mObject.addProperty("headname",mLedger.getLedgerName());
                mObject.addProperty("ledger_id",mLedger.getId());
                result.add(mObject);
            } else if(mLedger.getLedgerName().equals("PF A/c")){
                mObject.addProperty("headname",mLedger.getLedgerName());
                mObject.addProperty("ledger_id",mLedger.getId());
                result.add(mObject);
            } else if(mLedger.getLedgerName().equals("ESIC A/c")){
                mObject.addProperty("headname",mLedger.getLedgerName());
                mObject.addProperty("ledger_id",mLedger.getId());
                result.add(mObject);
            } else if(mLedger.getLedgerName().equals("PT A/c")){
                mObject.addProperty("headname",mLedger.getLedgerName());
                mObject.addProperty("ledger_id",mLedger.getId());
                result.add(mObject);
            } else if(mLedger.getLedgerName().equals("Insentive")){
                mObject.addProperty("headname",mLedger.getLedgerName());
                mObject.addProperty("ledger_id",mLedger.getId());
                result.add(mObject);
            }

        }
        response.addProperty("message", "success");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        response.add("result", result);
        return response;
    }
}

