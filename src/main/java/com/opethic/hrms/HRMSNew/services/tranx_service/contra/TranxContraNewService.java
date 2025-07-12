package com.opethic.hrms.HRMSNew.services.tranx_service.contra;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.common.GenerateDates;
import com.opethic.hrms.HRMSNew.common.GenerateFiscalYear;
import com.opethic.hrms.HRMSNew.common.LedgerCommonPostings;
import com.opethic.hrms.HRMSNew.dto.ContraMasterDTDTO;
import com.opethic.hrms.HRMSNew.dto.GenericDTData;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionPostings;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.models.report.DayBook;
import com.opethic.hrms.HRMSNew.models.tranx.contra.TranxContraDetails;
import com.opethic.hrms.HRMSNew.models.tranx.contra.TranxContraMaster;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionPostingsRepository;
import com.opethic.hrms.HRMSNew.repositories.master.TransactionTypeMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.report_repository.DaybookRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.contra_repository.TranxContraDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.contra_repository.TranxContraMasterRepository;
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
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class TranxContraNewService {

    @Autowired
    private JwtTokenUtil jwtRequestFilter;
    @Autowired
    private LedgerMasterRepository ledgerMasterRepository;
    @Autowired
    private LedgerTransactionDetailsRepository transactionDetailsRepository;
    @Autowired
    private TransactionTypeMasterRepository tranxRepository;
    @Autowired
    private GenerateFiscalYear generateFiscalYear;

    @Autowired
    private TranxContraMasterRepository tranxContaMasterRepository;
    @Autowired
    private TranxContraDetailsRepository tranxContraDetailsRepository;

    @Autowired
    private DaybookRepository daybookRepository;
    @Autowired
    private LedgerCommonPostings ledgerCommonPostings;
    @Autowired
    private LedgerTransactionPostingsRepository ledgerTransactionPostingsRepository;

    @PersistenceContext
    private EntityManager entityManager;

    private static final Logger contraLogger = LogManager.getLogger(TranxContraNewService.class);


    public JsonObject contraLastRecord(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
//        Long count = tranxContaMasterRepository.findLastRecord(users.getOutlet().getId());


        Long count = 0L;
        if (users.getBranch() != null) {
            count = tranxContaMasterRepository.findBranchLastRecord(users.getCompany().getId(), users.getBranch().getId());
        } else {
            count = tranxContaMasterRepository.findLastRecord(users.getCompany().getId());
        }

        String serailNo = String.format("%05d", count + 1);// 5 digit serial number
        GenerateDates generateDates = new GenerateDates();
        String currentMonth = generateDates.getCurrentMonth().substring(0, 3);
        String csCode = "CNTR" + currentMonth + serailNo;
        JsonObject result = new JsonObject();
        result.addProperty("message", "success");
        result.addProperty("responseStatus", HttpStatus.OK.value());
        result.addProperty("count", count + 1);
        result.addProperty("contraNo", csCode);
        return result;
    }


    public JsonObject createContra(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonObject response = new JsonObject();

        TranxContraMaster contraMaster = new TranxContraMaster();
        Branch branch = null;
        if (users.getBranch() != null)
            branch = users.getBranch();
        Company company = users.getCompany();
        contraMaster.setBranch(branch);
        contraMaster.setCompany(company);
        contraMaster.setStatus(true);
        LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
        /* fiscal year mapping */
        FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(tranxDate);
        if (fiscalYear != null) {
            contraMaster.setFiscalYear(fiscalYear);
            contraMaster.setFinancialYear(fiscalYear.getFiscalYear());
        }

        contraMaster.setTranscationDate(tranxDate);
        contraMaster.setContraSrNo(Long.parseLong(request.getParameter("voucher_contra_sr_no")));
        contraMaster.setContraNo(request.getParameter("voucher_contra_no"));
        contraMaster.setTotalAmt(Double.parseDouble(request.getParameter("total_amt")));
        if (paramMap.containsKey("narration"))
            contraMaster.setNarrations(request.getParameter("narration"));
        else {
            contraMaster.setNarrations("NA");
        }
        contraMaster.setCreatedBy(users.getId());
        TranxContraMaster tranxContraMaster = tranxContaMasterRepository.save(contraMaster);

        try {
            double total_amt = 0.0;
            String jsonStr = request.getParameter("rows");
            JsonParser parser = new JsonParser();
            JsonArray row = parser.parse(jsonStr).getAsJsonArray();
            for (int i = 0; i < row.size(); i++) {
                JsonObject contraRow = row.get(i).getAsJsonObject();
                TranxContraDetails tranxContraDetails = new TranxContraDetails();
                LedgerMaster ledgerMaster = null;

                tranxContraDetails.setBranch(branch);
                tranxContraDetails.setCompany(company);
                tranxContraDetails.setStatus(true);
                ledgerMaster = ledgerMasterRepository.findByIdAndStatus(contraRow.get("perticulars").getAsJsonObject().get("id").getAsLong(), true);
                if (ledgerMaster != null)
                    tranxContraDetails.setLedgerMaster(ledgerMaster);
                tranxContraDetails.setTranxContraMaster(tranxContraMaster);
                tranxContraDetails.setType(contraRow.get("type").getAsJsonObject().get("type").getAsString());
//                tranxContraDetails.setLedgerName(contraRow.get("perticulars").getAsJsonObject().get("ledger_name").getAsString());
                total_amt = contraRow.get("paid_amt").getAsDouble();
                if (contraRow.has("bank_payment_type"))
                    tranxContraDetails.setPayment_type(contraRow.get("bank_payment_type").getAsString());
                tranxContraDetails.setPaidAmount(total_amt);

                if (contraRow.has("bank_payment_no"))
                    tranxContraDetails.setBankPaymentNo(contraRow.get("bank_payment_no").getAsString());

                JsonObject perticulars = contraRow.get("perticulars").getAsJsonObject();

                //   ledgerMaster = ledgerMasterRepository.findByIdAndStatus(perticulars.get("id").getAsLong(), true);
                if (perticulars.get("type").getAsString().equalsIgnoreCase("bank_account"))
                    tranxContraDetails.setBankName(perticulars.get("label").getAsString());
                else {
                    tranxContraDetails.setBankName("Cash A/c");
                }

                tranxContraDetails.setLedgerType(ledgerMaster.getSlugName());
                tranxContraDetails.setCreatedBy(users.getId());

                TranxContraDetails mContra = tranxContraDetailsRepository.save(tranxContraDetails);
                insertIntoPostings(mContra, total_amt, contraRow.get("type").getAsJsonObject().get("type").getAsString(), "Insert");
                //Accounting Postings
            }
            response.addProperty("message", "Contra created successfully");
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            contraLogger.error("Error in createContra :->" + e.getMessage());
            response.addProperty("message", "Error in Contra creation");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    private void insertIntoPostings(TranxContraDetails mContra, double total_amt, String crdrType,
                                    String operation) {
        TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("CNTR");
        try {
            /**** New Postings Logic *****/
            ledgerCommonPostings.callToPostings(total_amt, mContra.getLedgerMaster(), tranxType,
                    mContra.getLedgerMaster().getAssociateGroups(), mContra.getTranxContraMaster().getFiscalYear(),
                    mContra.getBranch(), mContra.getCompany(), mContra.getTranxContraMaster().getTranscationDate(),
                    mContra.getTranxContraMaster().getId(), mContra.getTranxContraMaster().getContraNo(),
                    crdrType, true, "Contra", operation);
            /**** Save into Day Book ****/
            if (mContra.getType().equalsIgnoreCase("dr")) {
                saveIntoDayBook(mContra);
            }

        } catch (Exception e) {
            e.printStackTrace();
            contraLogger.error("Error in insertIntoPostings :->" + e.getMessage());
        }
    }

    private void saveIntoDayBook(TranxContraDetails mContra) {
        DayBook dayBook = new DayBook();
        dayBook.setCompany(mContra.getCompany());
        if (mContra.getBranch() != null)
            dayBook.setBranch(mContra.getBranch());
        dayBook.setAmount(mContra.getPaidAmount());
        dayBook.setTranxDate(mContra.getTranxContraMaster().getTranscationDate());
        dayBook.setParticulars(mContra.getLedgerMaster().getLedgerName());
        dayBook.setVoucherNo(mContra.getTranxContraMaster().getContraNo());
        dayBook.setVoucherType("Contra");
        dayBook.setStatus(true);
        daybookRepository.save(dayBook);
    }

    public JsonObject contraListbyCompany(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<TranxContraMaster> contra = new ArrayList<>();
        if (users.getBranch() != null) {
            contra = tranxContaMasterRepository.
                    findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(users.getCompany().getId(), users.getBranch().getId(), true);
        } else {
            contra = tranxContaMasterRepository.
                    findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
        }

        for (TranxContraMaster vouchers : contra) {
            JsonObject response = new JsonObject();
            response.addProperty("id", vouchers.getId());
            response.addProperty("contra_code", vouchers.getContraNo());
            response.addProperty("transaction_dt", vouchers.getTranscationDate().toString());
            response.addProperty("contra_sr_no", vouchers.getContraSrNo());
            response.addProperty("narration", vouchers.getNarrations());
            List<TranxContraDetails> tranxContraDetails = tranxContraDetailsRepository.findLedgerName(vouchers.getId(), users.getCompany().getId(), true);
            response.addProperty("ledger_name", tranxContraDetails != null && tranxContraDetails.size()>0 ? tranxContraDetails.get(0).getLedgerMaster().getLedgerName() : "");
            response.addProperty("total_amount", vouchers.getTotalAmt());
            result.add(response);
        }

        JsonObject output = new JsonObject();
        output.addProperty("message", "success");
        output.addProperty("responseStatus", HttpStatus.OK.value());
        output.add("data", result);
        return output;
    }

    public JsonObject updateContra(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonObject response = new JsonObject();
        TranxContraMaster contraMaster = tranxContaMasterRepository.findByIdAndStatus(Long.parseLong(request.getParameter("contra_id")), true);

//        TranxContraMaster contraMaster = new TranxContraMaster();
        Branch branch = null;
        if (users.getBranch() != null)
            branch = users.getBranch();
        Company company = users.getCompany();
        contraMaster.setBranch(branch);
        contraMaster.setCompany(company);
        //   contraMaster.setStatus(true);
        LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
        /* fiscal year mapping */
        FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(tranxDate);
        if (fiscalYear != null) {
            contraMaster.setFiscalYear(fiscalYear);
            contraMaster.setFinancialYear(fiscalYear.getFiscalYear());
        }

        contraMaster.setTranscationDate(tranxDate);
        contraMaster.setContraSrNo(Long.parseLong(request.getParameter("voucher_contra_sr_no")));
        contraMaster.setContraNo(request.getParameter("voucher_contra_no"));
        contraMaster.setTotalAmt(Double.parseDouble(request.getParameter("total_amt")));
        if (paramMap.containsKey("narration"))
            contraMaster.setNarrations(request.getParameter("narration"));
        else {
            contraMaster.setNarrations("NA");
        }
        contraMaster.setCreatedBy(users.getId());
        //contraMaster.setUpdatedBy(users.getId());
        TranxContraMaster tranxContraMaster = tranxContaMasterRepository.save(contraMaster);

        try {
            double total_amt = 0.0;
            String jsonStr = request.getParameter("rows");
            JsonParser parser = new JsonParser();
            JsonArray row = parser.parse(jsonStr).getAsJsonArray();
            for (int i = 0; i < row.size(); i++) {
                JsonObject contraRow = row.get(i).getAsJsonObject();
                TranxContraDetails tranxContraDetails = null;
                Long detailsId = 0L;
                if (contraRow.has("details_id"))
                    detailsId = contraRow.get("details_id").getAsLong();
                if (detailsId != 0) {
                    tranxContraDetails = tranxContraDetailsRepository.findByIdAndStatus(detailsId, true);
                } else {
                    tranxContraDetails = new TranxContraDetails();
                    tranxContraDetails.setStatus(true);
                }
//                TranxContraDetails tranxContraDetails = new TranxContraDetails();
                LedgerMaster ledgerMaster = null;
                tranxContraDetails.setBranch(branch);
                tranxContraDetails.setCompany(company);
//               // tranxContraDetails.setStatus(true);
                ledgerMaster = ledgerMasterRepository.findByIdAndStatus(contraRow.get("perticulars").getAsJsonObject().get("id").getAsLong(), true);
                if (ledgerMaster != null)
                    tranxContraDetails.setLedgerMaster(ledgerMaster);
                tranxContraDetails.setTranxContraMaster(tranxContraMaster);
                tranxContraDetails.setType(contraRow.get("type").getAsJsonObject().get("type").getAsString());
//                tranxContraDetails.setLedgerName(contraRow.get("perticulars").getAsJsonObject().get("ledger_name").getAsString());
                total_amt = contraRow.get("paid_amt").getAsDouble();
                if (contraRow.has("bank_payment_type"))
                    tranxContraDetails.setPayment_type(contraRow.get("bank_payment_type").getAsString());
                tranxContraDetails.setPaidAmount(total_amt);

                if (contraRow.has("bank_payment_no"))
                    tranxContraDetails.setBankPaymentNo(contraRow.get("bank_payment_no").getAsString());

                JsonObject perticulars = contraRow.get("perticulars").getAsJsonObject();

                //   ledgerMaster = ledgerMasterRepository.findByIdAndStatus(perticulars.get("id").getAsLong(), true);
                if (perticulars.get("type").getAsString().equalsIgnoreCase("bank_account"))
                    tranxContraDetails.setBankName(perticulars.get("label").getAsString());
                else {
                    tranxContraDetails.setBankName("Cash A/c");
                }

                tranxContraDetails.setLedgerType(ledgerMaster.getSlugName());
                tranxContraDetails.setCreatedBy(users.getId());

                TranxContraDetails mContra = tranxContraDetailsRepository.save(tranxContraDetails);
                updateIntoPostings(mContra, total_amt, detailsId);
            }
            response.addProperty("message", "Contra updated successfully");
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            contraLogger.error("Error in update Contra :->" + e.getMessage());
            response.addProperty("message", "Error in Contra creation");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }


    private void updateIntoPostings(TranxContraDetails mContra, double total_amt, Long detailsId) {
        try {
            TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("CNTR");
            if (mContra.getType().equalsIgnoreCase("dr")) {
                if (detailsId != 0) {
                    LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.
                            findByLedgerMasterIdAndTransactionTypeIdAndTransactionId(mContra.getLedgerMaster().getId(),
                                    tranxType.getId(), mContra.getTranxContraMaster().getId());
                    if (mLedger != null) {
                        mLedger.setAmount(total_amt);
                        mLedger.setTransactionDate(mContra.getTranxContraMaster().getTranscationDate());
                        mLedger.setOperations("updated");
                        ledgerTransactionPostingsRepository.save(mLedger);
                    }
                } else {
                    ledgerCommonPostings.callToPostings(total_amt, mContra.getLedgerMaster(), tranxType,
                            mContra.getLedgerMaster().getAssociateGroups(), mContra.getTranxContraMaster().getFiscalYear(), mContra.getBranch(),
                            mContra.getCompany(), mContra.getTranxContraMaster().getTranscationDate(),
                            mContra.getTranxContraMaster().getId(), mContra.getTranxContraMaster().getContraNo(),
                            "DR", true, "Contra", "Insert");
                }

            } else {
                if (detailsId != 0) {
                    LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.
                            findByLedgerMasterIdAndTransactionTypeIdAndTransactionId(mContra.getLedgerMaster().getId(),
                                    tranxType.getId(), mContra.getTranxContraMaster().getId());
                    if (mLedger != null) {
                        mLedger.setAmount(total_amt);
                        mLedger.setTransactionDate(mContra.getTranxContraMaster().getTranscationDate());
                        mLedger.setOperations("updated");
                        ledgerTransactionPostingsRepository.save(mLedger);
                    }
                } else {
                    ledgerCommonPostings.callToPostings(total_amt, mContra.getLedgerMaster(), tranxType,
                            mContra.getLedgerMaster().getAssociateGroups(), mContra.getTranxContraMaster().getFiscalYear(), mContra.getBranch(),
                            mContra.getCompany(), mContra.getTranxContraMaster().getTranscationDate(),
                            mContra.getTranxContraMaster().getId(), mContra.getTranxContraMaster().getContraNo(),
                            "CR", true, "Contra", "Insert");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            contraLogger.error("Error in updateIntoPostings :->" + e.getMessage());
        }
    }

    /*get contra by id*/
    public JsonObject getContraById(HttpServletRequest request) {

        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<TranxContraDetails> list = new ArrayList<>();

        JsonObject finalResult = new JsonObject();
        try {
            Long contraId = Long.parseLong(request.getParameter("contra_id"));
            TranxContraMaster contraMaster = tranxContaMasterRepository.findByIdAndCompanyIdAndStatus(contraId, users.getCompany().getId(), true);

            list = tranxContraDetailsRepository.findByTranxContraMasterIdAndStatus(contraMaster.getId(), true);
            finalResult.addProperty("contra_no", contraMaster.getContraNo());
            finalResult.addProperty("contra_sr_no", contraMaster.getContraSrNo());
            finalResult.addProperty("tranx_date", contraMaster.getTranscationDate().toString());
            finalResult.addProperty("total_amt", contraMaster.getTotalAmt());
            finalResult.addProperty("narrations", contraMaster.getNarrations());

            JsonArray row = new JsonArray();
            if (list.size() > 0) {
                for (TranxContraDetails mdetails : list) {
                    JsonObject rpdetails = new JsonObject();
                    rpdetails.addProperty("details_id", mdetails.getId());
                    rpdetails.addProperty("type", mdetails.getType());
                    rpdetails.addProperty("ledger_type", mdetails.getLedgerType());
                    rpdetails.addProperty("ledger_name", mdetails.getLedgerName());
                    rpdetails.addProperty("paid_amt", mdetails.getPaidAmount());
//                    rpdetails.addProperty("dr",mdetails.getDr());
//                    rpdetails.addProperty("cr",mdetails.getCr());
                    rpdetails.addProperty("payment_type", mdetails.getPayment_type());
                    rpdetails.addProperty("payment_no", mdetails.getBankPaymentNo());
                    rpdetails.addProperty("bankName", mdetails.getBankName());
                    rpdetails.addProperty("ledger_id", mdetails.getLedgerMaster().getId());
                    row.add(rpdetails);
                }
            }

            finalResult.addProperty("message", "success");
            finalResult.addProperty("responseStatus", HttpStatus.OK.value());
            finalResult.add("contra_details", row);

        } catch (DataIntegrityViolationException e) {
            e.printStackTrace();
            contraLogger.error("Error in getContraById" + e.getMessage());
            System.out.println(e.getMessage());
            e.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.CONFLICT.value());
        } catch (Exception e1) {
            e1.printStackTrace();
            contraLogger.error("Error in getContraById" + e1.getMessage());
            System.out.println(e1.getMessage());
            e1.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        return finalResult;
    }

    public JsonObject deleteContra(HttpServletRequest request) {
        JsonObject jsonObject = new JsonObject();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        TranxContraMaster contraTranx = tranxContaMasterRepository.findByIdAndStatus(Long.parseLong(request.getParameter("id")), true);
        TranxContraMaster mContra;
        try {
            contraTranx.setStatus(false);
            mContra = tranxContaMasterRepository.save(contraTranx);
            if (contraTranx != null) {
                List<TranxContraDetails> tranxContraDetails = tranxContraDetailsRepository.
                        findByTranxContraMasterIdAndStatus(contraTranx.getId(), true);
                for (TranxContraDetails mDetail : tranxContraDetails) {
                    if (mDetail.getType().equalsIgnoreCase("CR"))
                        insertIntoPostings(mDetail, mDetail.getPaidAmount(), "DR", "Delete");// Accounting Postings
                    else
                        insertIntoPostings(mDetail, mDetail.getPaidAmount(), "CR", "Delete");// Accounting Postings
                }
                jsonObject.addProperty("message", "Contra invoice deleted successfully");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                jsonObject.addProperty("message", "error in sales quotation deletion");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e) {
            contraLogger.error("Error in Contra invoice Delete()->" + e.getMessage());
        }
        return jsonObject;
    }

    public Object DTContraList(Map<String, String> request, HttpServletRequest httpServletRequest) {
        Integer from = Integer.parseInt(request.get("from"));
        Integer to = Integer.parseInt(request.get("to"));
        String searchText = request.get("searchText");
        Users users = jwtRequestFilter.getUserDataFromToken(httpServletRequest.getHeader("Authorization").substring(7));
        GenericDTData genericDTData = new GenericDTData();
        List<TranxContraMaster> tranxContraMasterList = new ArrayList<>();
        List<ContraMasterDTDTO> contraMasterDTDTOList = new ArrayList<>();
        String query = "";
        try {
            if (users.getBranch() != null) {
//                receipt = repository.findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(users.getCompany().getId(), users.getBranch()().getId(), true);
//                query = "SELECT * FROM `tranx_receipt_master_tbl` WHERE company_id="+users.getCompany().getId()+" AND branch_id="+users.getBranch()().getId()+" " +
//                        "AND tranx_receipt_master_tbl.status=1";
                query="SELECT * FROM `tranx_contra_master_tbl` WHERE company_id="+users.getCompany().getId()+" AND branch_id="+users.getBranch().getId()+" AND status=1 ORDER BY id DESC";
            } else {
//                receipt = repository.findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
//                query = "SELECT * FROM `tranx_receipt_master_tbl` WHERE company_id="+users.getCompany().getId()+" AND tranx_receipt_master_tbl.status=1";
                query="SELECT * FROM `tranx_contra_master_tbl` WHERE company_id="+users.getCompany().getId()+" AND status=1 ORDER BY id DESC";
            }


            if (!searchText.equalsIgnoreCase("")) {
                query = query + " AND (contra_no LIKE '%" + searchText + "%' OR narration LIKE '%" +
                        searchText + "%')";
            }

            String jsonToStr = request.get("sort");
            JsonObject jsonObject = new Gson().fromJson(jsonToStr, JsonObject.class);
            if (!jsonObject.get("colId").toString().equalsIgnoreCase("null") &&
                    jsonObject.get("colId").toString() != null) {
                System.out.println(" ORDER BY " + jsonObject.get("colId").toString());
                String sortBy = jsonObject.get("colId").toString();
                query = query + " ORDER BY " + sortBy;
                if (jsonObject.get("isAsc").getAsBoolean()) {
                    query = query + " ASC";
                } else {
                    query = query + " DESC";
                }
            }
            String query1 = query;
            Integer endLimit = to - from;
            query = query + " LIMIT " + from + ", " + endLimit;
            System.out.println("query " + query);

            Query q = entityManager.createNativeQuery(query, TranxContraMaster.class);
            Query q1 = entityManager.createNativeQuery(query1, TranxContraMaster.class);

            tranxContraMasterList = q.getResultList();
            System.out.println("Limit total rows " + tranxContraMasterList);

            for (TranxContraMaster tranxContraMaster : tranxContraMasterList) {
                contraMasterDTDTOList.add(convertToDTDTO(tranxContraMaster));
            }

            List<TranxContraMaster> tranxContraMasterArrayList = new ArrayList<>();
            tranxContraMasterArrayList = q1.getResultList();
            System.out.println("total rows " + tranxContraMasterList.size());

            genericDTData.setRows(contraMasterDTDTOList);
            genericDTData.setTotalRows(tranxContraMasterList.size());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Exception " + e.getMessage());
            genericDTData.setRows(contraMasterDTDTOList);
            genericDTData.setTotalRows(0);
        }
        return genericDTData;
    }
    private ContraMasterDTDTO convertToDTDTO(TranxContraMaster rMaster) {
        ContraMasterDTDTO contraMaster = new ContraMasterDTDTO();
        contraMaster.setId(rMaster.getId());
        contraMaster.setContraNo(rMaster.getContraNo());
        contraMaster.setContraSrNo(rMaster.getContraSrNo());
//        paymentMaster.setTranxReceiptPerticulars(rMaster.getTranxReceiptPerticulars().size() > 0 ? rMaster.getTranxReceiptPerticulars().get(0).getLedgerName() : "");
        contraMaster.setTranscationDate(rMaster.getTranscationDate());
        contraMaster.setNarrations(rMaster.getNarrations());
        contraMaster.setTotalAmt(rMaster.getTotalAmt());
        contraMaster.setStatus(true);
        contraMaster.setCreatedAt(LocalDateTime.parse(String.valueOf(rMaster.getCreatedAt())));
        return contraMaster;
    }
}
