package com.opethic.hrms.HRMSNew.services.tranx_service.journal;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.opethic.hrms.HRMSNew.common.GenerateDates;
import com.opethic.hrms.HRMSNew.common.GenerateFiscalYear;
import com.opethic.hrms.HRMSNew.common.LedgerCommonPostings;
import com.opethic.hrms.HRMSNew.models.ledger_details.LedgerTransactionPostings;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.models.report.DayBook;
import com.opethic.hrms.HRMSNew.models.tranx.journal.TranxJournalDetails;
import com.opethic.hrms.HRMSNew.models.tranx.journal.TranxJournalMaster;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerTransactionPostingsRepository;
import com.opethic.hrms.HRMSNew.repositories.master.TransactionTypeMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.report_repository.DaybookRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.journal_repository.TranxJournalDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.journal_repository.TranxJournalMasterRepository;
import com.opethic.hrms.HRMSNew.util.JwtTokenUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class TranxJournalService {
    @Autowired
    private TranxJournalMasterRepository tranxJournalMasterRepository;
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

    private TranxJournalDetailsRepository tranxJournalDetailsRepository;

    @Autowired
    private DaybookRepository daybookRepository;
    @Autowired
    private LedgerCommonPostings ledgerCommonPostings;
    @Autowired
    private LedgerTransactionPostingsRepository ledgerTransactionPostingsRepository;
    private static final Logger journalLogger = LogManager.getLogger(TranxJournalService.class);


    public JsonObject journalLastRecord(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));

        Long count = 0L;
        if (users.getBranch() != null) {
            count = tranxJournalMasterRepository.findBranchLastRecord(users.getCompany().getId(), users.getBranch().getId());
        } else {
            count = tranxJournalMasterRepository.findLastRecord(users.getCompany().getId());
        }
//        Long count = tranxJournalMasterRepository.findLastRecord(users.getCompany()().getId());
        String serailNo = String.format("%05d", count + 1);// 5 digit serial number
        GenerateDates generateDates = new GenerateDates();
        String currentMonth = generateDates.getCurrentMonth().substring(0, 3);
        String csCode = "JRNL" + currentMonth + serailNo;
        JsonObject result = new JsonObject();
        result.addProperty("message", "success");
        result.addProperty("responseStatus", HttpStatus.OK.value());
        result.addProperty("journal_sr_no", count + 1);
        result.addProperty("journal_code", csCode);
        return result;
    }


    public JsonObject getledgerDetails(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        JsonArray result = new JsonArray();
        List<LedgerMaster> ledgerMaster = new ArrayList<>();
        if (users.getBranch() != null) {
            ledgerMaster = ledgerMasterRepository.findledgersByBranch(users.getCompany().getId(), users.getBranch().getId());
        } else {
            ledgerMaster = ledgerMasterRepository.findledgers(users.getCompany().getId());
        }
        JsonObject response = new JsonObject();
        for (LedgerMaster mLedger : ledgerMaster) {
            JsonObject jsonObject = new JsonObject();
            jsonObject.addProperty("id", mLedger.getId());
            jsonObject.addProperty("name", mLedger.getLedgerName());
            jsonObject.addProperty("type", mLedger.getSlugName());
            result.add(jsonObject);
        }
        if (result.size() > 0) {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "success");
            response.add("list", result);
        } else {
            response.addProperty("responseStatus", HttpStatus.OK.value());
            response.addProperty("message", "empty list");
            response.add("list", result);
        }
        return response;
    }

    public JsonObject createJournal(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonObject response = new JsonObject();
        TranxJournalMaster journalMaster = new TranxJournalMaster();
        Branch branch = null;
        if (users.getBranch() != null)
            branch = users.getBranch();
        Company company = users.getCompany();
        journalMaster.setBranch(branch);
        journalMaster.setCompany(company);
        journalMaster.setStatus(true);
        LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
        /* fiscal year mapping */
        FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(tranxDate);
        if (fiscalYear != null) {
            journalMaster.setFiscalYear(fiscalYear);
            journalMaster.setFinancialYear(fiscalYear.getFiscalYear());
        }

        journalMaster.setTranscationDate(tranxDate);
        journalMaster.setJournalSrNo(Long.parseLong(request.getParameter("journal_sr_no")));
        journalMaster.setJournalNo(request.getParameter("journal_code"));
        journalMaster.setTotalAmt(Double.parseDouble(request.getParameter("total_amt")));
        if (paramMap.containsKey("narration"))
            journalMaster.setNarrations(request.getParameter("narration"));
        else {
            journalMaster.setNarrations("NA");
        }
        journalMaster.setCreatedBy(users.getId());
        TranxJournalMaster tranxJournalMaster = tranxJournalMasterRepository.save(journalMaster);
        try {
            double total_amt = 0.0;
            String jsonStr = request.getParameter("rows");
            JsonParser parser = new JsonParser();
            JsonArray row = parser.parse(jsonStr).getAsJsonArray();
            for (int i = 0; i < row.size(); i++) {
                JsonObject journalRow = row.get(i).getAsJsonObject();
                TranxJournalDetails tranxJournalDetails = new TranxJournalDetails();
                LedgerMaster ledgerMaster = null;

                tranxJournalDetails.setBranch(branch);
                tranxJournalDetails.setCompany(company);
                tranxJournalDetails.setStatus(true);
                ledgerMaster = ledgerMasterRepository.findByIdAndStatus(journalRow.get("perticulars").getAsJsonObject().get("id").getAsLong(), true);
                if (ledgerMaster != null)
                    tranxJournalDetails.setLedgerMaster(ledgerMaster);
                tranxJournalDetails.setTranxJournalMaster(tranxJournalMaster);
                tranxJournalDetails.setType(journalRow.get("type").getAsJsonObject().get("type").getAsString());
//                tranxContraDetails.setLedgerName(contraRow.get("perticulars").getAsJsonObject().get("ledger_name").getAsString());
                total_amt = journalRow.get("paid_amt").getAsDouble();

                JsonObject perticulars = journalRow.get("perticulars").getAsJsonObject();
                tranxJournalDetails.setLedgerType(ledgerMaster.getSlugName());
                tranxJournalDetails.setCreatedBy(users.getId());
                tranxJournalDetails.setPaidAmount(total_amt);
                TranxJournalDetails mContra = tranxJournalDetailsRepository.save(tranxJournalDetails);
                insertIntoPostings(mContra, total_amt, journalRow.get("type").getAsJsonObject().get("type").getAsString(), "Insert");//Accounting Postings
            }
            response.addProperty("message", "Journal created successfully");
            response.addProperty("responseStatus", HttpStatus.OK.value());
        } catch (Exception e) {
            e.printStackTrace();
            journalLogger.error("Error in createJournal :->" + e.getMessage());
            response.addProperty("message", "Error in Journal creation");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        return response;
    }

    private void insertIntoPostings(TranxJournalDetails mjournal, double total_amt, String crdrType,
                                    String operation) {
        TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("JRNL");
        try {

            /**** New Postings Logic *****/
            ledgerCommonPostings.callToPostings(total_amt, mjournal.getLedgerMaster(), tranxType,
                    mjournal.getLedgerMaster().getAssociateGroups(), mjournal.getTranxJournalMaster().getFiscalYear(),
                    mjournal.getBranch(), mjournal.getCompany(), mjournal.getTranxJournalMaster().getTranscationDate(),
                    mjournal.getTranxJournalMaster().getId(), mjournal.getTranxJournalMaster().getJournalNo(),
                    crdrType, true, "Journal", operation);
            /**** Save into Day Book ****/
            if (crdrType.equalsIgnoreCase("dr") && operation.equalsIgnoreCase("Insert")) {
                saveIntoDayBook(mjournal);
            }

        } catch (Exception e) {
            e.printStackTrace();
            journalLogger.error("Error in journal insertIntoPostings :->" + e.getMessage());
        }
    }

    private void saveIntoDayBook(TranxJournalDetails mjournal) {
        DayBook dayBook = new DayBook();
        dayBook.setCompany(mjournal.getCompany());
        if (mjournal.getBranch() != null)
            dayBook.setBranch(mjournal.getBranch());
        dayBook.setAmount(mjournal.getPaidAmount());
        dayBook.setTranxDate(mjournal.getTranxJournalMaster().getTranscationDate());
        dayBook.setParticulars(mjournal.getLedgerMaster().getLedgerName());
        dayBook.setVoucherNo(mjournal.getTranxJournalMaster().getJournalNo());
        dayBook.setVoucherType("Journal");
        dayBook.setStatus(true);
        daybookRepository.save(dayBook);
    }

    public JsonObject journalListbyCompany(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        List<TranxJournalMaster> journal = new ArrayList<>();
        if (users.getBranch() != null) {
            journal = tranxJournalMasterRepository.
                    findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(users.getCompany().getId(), users.getBranch().getId(), true);
        } else {
            journal = tranxJournalMasterRepository.
                    findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
        }
        for (TranxJournalMaster vouchers : journal) {
            JsonObject response = new JsonObject();
            response.addProperty("id", vouchers.getId());
            response.addProperty("journal_code", vouchers.getJournalNo());
            response.addProperty("transaction_dt", vouchers.getTranscationDate().toString());
            response.addProperty("journal_sr_no", vouchers.getJournalSrNo());
//             response.addProperty("ledger_name",vouchers.get );
           List<TranxJournalDetails>  tranxJournalDetails = tranxJournalDetailsRepository.findByTranxJournalMasterIdAndTypeAndStatus(vouchers.getId(), "dr", true);
            response.addProperty("ledger_name", tranxJournalDetails != null && tranxJournalDetails.size()>0 ? tranxJournalDetails.get(0).getLedgerMaster().getLedgerName() : "");
            response.addProperty("narration", vouchers.getNarrations());
            response.addProperty("total_amount", vouchers.getTotalAmt());
            result.add(response);
        }
        JsonObject output = new JsonObject();
        output.addProperty("message", "success");
        output.addProperty("responseStatus", HttpStatus.OK.value());
        output.add("data", result);
        return output;
    }

    /*update journal*/
    public JsonObject updateJournal(HttpServletRequest request) {
        JsonObject response = null;
        try {
            Users users = jwtRequestFilter.getUserDataFromToken(
                    request.getHeader("Authorization").substring(7));
            Map<String, String[]> paramMap = request.getParameterMap();
            response = new JsonObject();
            TranxJournalMaster journalMaster = tranxJournalMasterRepository.findByIdAndStatus(Long.parseLong(request.getParameter("journal_id")), true);
            Branch branch = null;
            if (users.getBranch() != null)
                branch = users.getBranch();
            Company company = users.getCompany();
            journalMaster.setBranch(branch);
            journalMaster.setCompany(company);
            //   journalMaster.setStatus(true);
            LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
            journalMaster.setTranscationDate(tranxDate);
            /* fiscal year mapping */
            FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(tranxDate);
            if (fiscalYear != null) {
                journalMaster.setFiscalYear(fiscalYear);
                journalMaster.setFinancialYear(fiscalYear.getFiscalYear());
            }
//        journalMaster.setTranscationDate(tranxDate);
            journalMaster.setJournalSrNo(Long.parseLong(request.getParameter("journal_sr_no")));
            journalMaster.setJournalNo(request.getParameter("journal_code"));
//            journalMaster.setTotalAmt(Double.parseDouble(request.getParameter("total_amt")));
            if (paramMap.containsKey("narration"))
                journalMaster.setNarrations(request.getParameter("narration"));
            else {
                journalMaster.setNarrations("NA");
            }
            journalMaster.setCreatedBy(users.getId());
            //    journalMaster.setUpdatedBy(users.getId());
            TranxJournalMaster tranxJournalMaster = tranxJournalMasterRepository.save(journalMaster);
            try {
                double total_amt = 0.0;
                String jsonStr = request.getParameter("rows");
                JsonParser parser = new JsonParser();
                JsonArray row = parser.parse(jsonStr).getAsJsonArray();
                for (int i = 0; i < row.size(); i++) {
                    JsonObject journalRow = row.get(i).getAsJsonObject();
                    TranxJournalDetails tranxJournalDetails = null;
                    Long detailsId = 0L;
                    if (journalRow.has("details_id"))
                        detailsId = journalRow.get("details_id").getAsLong();
                    if (detailsId != 0) {
                        tranxJournalDetails = tranxJournalDetailsRepository.findByIdAndStatus(detailsId, true);
                    } else {
                        tranxJournalDetails = new TranxJournalDetails();

                        tranxJournalDetails.setStatus(true);
                    }
////                TranxJournalDetails tranxJournalDetails = new TranxJournalDetails();
                    LedgerMaster ledgerMaster = null;

                    tranxJournalDetails.setBranch(branch);
                    tranxJournalDetails.setCompany(company);
////                tranxJournalDetails.setStatus(true);
                    ledgerMaster = ledgerMasterRepository.findByIdAndStatus(journalRow.get("perticulars").getAsJsonObject().get("id").getAsLong(), true);
                    if (ledgerMaster != null)
                        tranxJournalDetails.setLedgerMaster(ledgerMaster);
                    tranxJournalDetails.setTranxJournalMaster(tranxJournalMaster);
                    tranxJournalDetails.setType(journalRow.get("type").getAsJsonObject().get("type").getAsString());
////                tranxContraDetails.setLedgerName(contraRow.get("perticulars").getAsJsonObject().get("ledger_name").getAsString());
                    total_amt = journalRow.get("paid_amt").getAsDouble();

                    JsonObject perticulars = journalRow.get("perticulars").getAsJsonObject();
                    tranxJournalDetails.setLedgerType(ledgerMaster.getSlugName());
                    tranxJournalDetails.setCreatedBy(users.getId());
                    tranxJournalDetails.setPaidAmount(total_amt);
                    TranxJournalDetails mContra = tranxJournalDetailsRepository.save(tranxJournalDetails);
                    updateIntoPostings(mContra, total_amt, detailsId);
                }
                response.addProperty("message", "Journal created successfully");
                response.addProperty("responseStatus", HttpStatus.OK.value());
            } catch (Exception e) {
                e.printStackTrace();
                journalLogger.error("Error in createJournal :->" + e.getMessage());
                response.addProperty("message", "Error in Contra creation");
                response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
//            return response;
        } catch (Exception e) {
            e.printStackTrace();
            journalLogger.error("Error in createJournal :->" + e.getMessage());
        }
        return response;
    }

    private void updateIntoPostings(TranxJournalDetails mjournal, double total_amt, Long detailsId) {
        TransactionTypeMaster tranxType = tranxRepository.findByTransactionCodeIgnoreCase("JRNL");
        try {
            if (mjournal.getType().equalsIgnoreCase("dr")) {
                if (detailsId != 0) {
                    LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.
                            findByLedgerMasterIdAndTransactionTypeIdAndTransactionId(mjournal.getLedgerMaster().getId(),
                                    tranxType.getId(), mjournal.getTranxJournalMaster().getId());
                    if (mLedger != null) {
                        mLedger.setAmount(total_amt);
                        mLedger.setTransactionDate(mjournal.getTranxJournalMaster().getTranscationDate());
                        mLedger.setOperations("updated");
                        ledgerTransactionPostingsRepository.save(mLedger);
                    }
                } else {
                    ledgerCommonPostings.callToPostings(total_amt, mjournal.getLedgerMaster(), tranxType,
                            mjournal.getLedgerMaster().getAssociateGroups(), mjournal.getTranxJournalMaster().getFiscalYear(),
                            mjournal.getBranch(), mjournal.getCompany(), mjournal.getTranxJournalMaster().getTranscationDate(),
                            mjournal.getTranxJournalMaster().getId(), mjournal.getTranxJournalMaster().getJournalNo(),
                            "DR", true, "Journal", "Insert");
                }
            } else {
                if (detailsId != 0) {
                    LedgerTransactionPostings mLedger = ledgerTransactionPostingsRepository.
                            findByLedgerMasterIdAndTransactionTypeIdAndTransactionId(mjournal.getLedgerMaster().getId(),
                                    tranxType.getId(), mjournal.getTranxJournalMaster().getId());
                    if (mLedger != null) {
                        mLedger.setAmount(total_amt);
                        mLedger.setTransactionDate(mjournal.getTranxJournalMaster().getTranscationDate());
                        mLedger.setOperations("updated");
                        ledgerTransactionPostingsRepository.save(mLedger);
                    }
                } else {
                    /**** New Postings Logic *****/
                    ledgerCommonPostings.callToPostings(total_amt, mjournal.getLedgerMaster(), tranxType,
                            mjournal.getLedgerMaster().getAssociateGroups(), mjournal.getTranxJournalMaster().getFiscalYear(),
                            mjournal.getBranch(), mjournal.getCompany(), mjournal.getTranxJournalMaster().getTranscationDate(),
                            mjournal.getTranxJournalMaster().getId(), mjournal.getTranxJournalMaster().getJournalNo(),
                            "CR", true, "Journal", "Insert");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            journalLogger.error("Error in journal insertIntoPostings :->" + e.getMessage());
        }
    }

    /*get journal by id*/
    public JsonObject getjournalById(HttpServletRequest request) {

        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<TranxJournalDetails> list = new ArrayList<>();

        JsonObject finalResult = new JsonObject();
        try {
            Long journalId = Long.parseLong(request.getParameter("journal_id"));
            TranxJournalMaster journalMaster = tranxJournalMasterRepository.findByIdAndCompanyIdAndStatus(journalId, users.getCompany().getId(), true);

            list = tranxJournalDetailsRepository.findByTranxJournalMasterIdAndStatus(journalMaster.getId(), true);
            finalResult.addProperty("journal_id",journalMaster.getId());
            finalResult.addProperty("journal_code", journalMaster.getJournalNo());
            finalResult.addProperty("journal_sr_no", journalMaster.getJournalSrNo());
            finalResult.addProperty("tranx_date", journalMaster.getTranscationDate().toString());
            finalResult.addProperty("total_amt", journalMaster.getTotalAmt());
            finalResult.addProperty("narrations", journalMaster.getNarrations());
            JsonArray row = new JsonArray();
            if (list.size() > 0) {
                for (TranxJournalDetails mdetails : list) {
                    JsonObject rpdetails = new JsonObject();
                    rpdetails.addProperty("details_id", mdetails.getId());
                    rpdetails.addProperty("type", mdetails.getType());
                    rpdetails.addProperty("ledger_type", mdetails.getLedgerType());
                    rpdetails.addProperty("paid_amt", mdetails.getPaidAmount());

                    rpdetails.addProperty("ledger_id", mdetails.getLedgerMaster().getId());
                    row.add(rpdetails);
                }
            }

            finalResult.addProperty("message", "success");
            finalResult.addProperty("responseStatus", HttpStatus.OK.value());
            finalResult.add("journal_details", row);

        } catch (DataIntegrityViolationException e) {
            e.printStackTrace();
            journalLogger.error("Error in getJournalById" + e.getMessage());
            System.out.println(e.getMessage());
            e.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.CONFLICT.value());
        } catch (Exception e1) {
            e1.printStackTrace();
            journalLogger.error("Error in getJournalById" + e1.getMessage());
            System.out.println(e1.getMessage());
            e1.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        return finalResult;
    }

    public JsonObject deleteJournal(HttpServletRequest request) {
        JsonObject jsonObject = new JsonObject();
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        TranxJournalMaster journalMaster = tranxJournalMasterRepository.findByIdAndStatus(Long.parseLong(request.getParameter("id")), true);
        try {
            journalMaster.setStatus(false);
            tranxJournalMasterRepository.save(journalMaster);
            if (journalMaster != null) {
                List<TranxJournalDetails> tranxJournalDetails = tranxJournalDetailsRepository.
                        findByTranxJournalMasterIdAndStatus(journalMaster.getId(), true);
                for (TranxJournalDetails mDetail : tranxJournalDetails) {
                    if (mDetail.getType().equalsIgnoreCase("CR"))
                        insertIntoPostings(mDetail, mDetail.getPaidAmount(), "DR", "Delete");// Accounting Postings
                    else
                        insertIntoPostings(mDetail, mDetail.getPaidAmount(), "CR", "Delete");// Accounting Postings
                }
                jsonObject.addProperty("message", "Journal invoice deleted successfully");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            } else {
                jsonObject.addProperty("message", "error in journal deletion");
                jsonObject.addProperty("responseStatus", HttpStatus.OK.value());
            }
        } catch (Exception e) {
            journalLogger.error("Error in journal invoice Delete()->" + e.getMessage());
        }
        return jsonObject;
    }
}
