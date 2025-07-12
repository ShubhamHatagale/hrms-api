package com.opethic.hrms.HRMSNew.services.tranx_service.gstinput;

import com.google.gson.*;
import com.opethic.hrms.HRMSNew.common.GenerateDates;
import com.opethic.hrms.HRMSNew.common.GenerateFiscalYear;
import com.opethic.hrms.HRMSNew.models.master.*;
import com.opethic.hrms.HRMSNew.models.tranx.gstinput.GstInputDetails;
import com.opethic.hrms.HRMSNew.models.tranx.gstinput.GstInputDutiesTaxes;
import com.opethic.hrms.HRMSNew.models.tranx.gstinput.GstInputMaster;
import com.opethic.hrms.HRMSNew.repositories.ledgerdetails_repo.LedgerMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.master.PaymentModeMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.master.TaxMasterRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.gstinput_repository.GstInputDetailsRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.gstinput_repository.GstInputDutiesTaxesRepository;
import com.opethic.hrms.HRMSNew.repositories.tranx_repository.gstinput_repository.GstInputMasterRepository;
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
public class TranxGstInputService {
    @Autowired
    private JwtTokenUtil jwtRequestFilter;
    @Autowired
    private GstInputMasterRepository gstInputMasterRepository;
    @Autowired
    private GstInputDetailsRepository gstInputDetailsRepository;
    @Autowired
    private GenerateFiscalYear generateFiscalYear;

    private static final Logger gstInputLogger = LogManager.getLogger(TranxGstInputService.class);
    @Autowired
    private LedgerMasterRepository ledgerMasterRepository;
    @Autowired
    private PaymentModeMasterRepository paymentModeMasterRepository;
//    @Autowired
//    private ProductRepository productRepository;
//    @Autowired
//    private ProductHsnRepository productHsnRepository;
    @Autowired
    private TaxMasterRepository taxMasterRepository;
    @Autowired
    private GstInputDutiesTaxesRepository gstInputDutiesTaxesRepository;

    public JsonObject gstInputLastRecord(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        Long count = 0L;
        if (users.getBranch() != null) {
            count = gstInputMasterRepository.findBranchLastRecord(users.getCompany().getId(), users.getBranch().getId());
        } else {
            count = gstInputMasterRepository.findLastRecord(users.getCompany().getId());
        }
        String serailNo = String.format("%05d", count + 1);// 5 digit serial number
        GenerateDates generateDates = new GenerateDates();
        String currentMonth = generateDates.getCurrentMonth().substring(0, 3);
        String csCode = "GSTINPUT" + currentMonth + serailNo;
        JsonObject result = new JsonObject();
        result.addProperty("message", "success");
        result.addProperty("responseStatus", HttpStatus.OK.value());
        result.addProperty("count", count + 1);
        result.addProperty("gstInputNo", csCode);
        return result;
    }

    public JsonObject createGstInput(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonObject response = new JsonObject();
        GstInputMaster gstInputMaster = new GstInputMaster();
        Branch branch = null;
        try {
            if (users.getBranch() != null)
                branch = users.getBranch();
            Company company = users.getCompany();
            gstInputMaster.setBranch(branch);
            gstInputMaster.setCompany(company);
            gstInputMaster.setStatus(true);
            LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
            LocalDate voucherDate = LocalDate.parse(request.getParameter("voucher_dt"));
            /* fiscal year mapping */
            FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(voucherDate);
            if (fiscalYear != null) {
                gstInputMaster.setFiscalYear(fiscalYear);
            }
            gstInputMaster.setTranxDate(tranxDate);
            gstInputMaster.setVoucherDate(voucherDate);
            gstInputMaster.setVoucherSrNo(request.getParameter("voucher_sr_no"));
            gstInputMaster.setVoucherNo(request.getParameter("voucher_no"));
            gstInputMaster.setTotalAmount(Double.parseDouble(request.getParameter("grand_total")));
            if (paramMap.containsKey("narration"))
                gstInputMaster.setNarrations(request.getParameter("narration"));
            gstInputMaster.setCreatedBy(users.getId());
            gstInputMaster.setTotalCgst(Double.parseDouble(request.getParameter("totalcgst")));
            gstInputMaster.setTotalSgst(Double.parseDouble(request.getParameter("totalsgst")));
            gstInputMaster.setTotalIgst(Double.parseDouble(request.getParameter("totaligst")));
            LedgerMaster supplier = ledgerMasterRepository.findByIdAndStatus(Long.parseLong(
                    request.getParameter("partyNameId")), true);
            gstInputMaster.setSupplierLedger(supplier);
            LedgerMaster postingAcct = ledgerMasterRepository.findByIdAndStatus(Long.parseLong(
                    request.getParameter("postingAccId")), true);
            gstInputMaster.setPostingLedger(postingAcct);
            PaymentModeMaster paymentModeMaster = paymentModeMasterRepository.findById(Long.parseLong(
                    request.getParameter("pay_mode"))).get();
            gstInputMaster.setPaymentModeMaster(paymentModeMaster);
            LedgerMaster roundoff = null;
            if (users.getBranch() != null)
                roundoff = ledgerMasterRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCase(
                        users.getCompany().getId(), users.getBranch().getId(), "Round off");
            else
                roundoff = ledgerMasterRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndBranchIsNull(
                        users.getCompany().getId(), "Round off");
            gstInputMaster.setRoundOff(Double.parseDouble(request.getParameter("round_off_amt")));
            gstInputMaster.setRoundOffLedger(roundoff);
            GstInputMaster tranxGstInput = gstInputMasterRepository.save(gstInputMaster);

            /**** Details  ****/
            String jsonStr = request.getParameter("rows");
            JsonParser parser = new JsonParser();
            JsonArray row = parser.parse(jsonStr).getAsJsonArray();
            for (int i = 0; i < row.size(); i++) {
                JsonObject gstInputRow = row.get(i).getAsJsonObject();
                GstInputDetails gstInputDetails = new GstInputDetails();
                gstInputDetails.setGstInputMaster(tranxGstInput);
                gstInputDetails.setParticular(gstInputRow.get("name").getAsString());
//                ProductHsn hsn = productHsnRepository.findByIdAndStatus(
//                        gstInputRow.get("hsn_selected").getAsLong(), true);
//                gstInputDetails.setHsnNo(hsn.getHsnNumber());
//                gstInputDetails.setProductHsn(hsn);
                TaxMaster taxMaster = taxMasterRepository.findByIdAndStatus(
                        gstInputRow.get("tax_selected").getAsLong(), true);
                gstInputDetails.setTaxMaster(taxMaster);
                gstInputDetails.setIgst(gstInputRow.get("igst").getAsDouble());
                gstInputDetails.setCgst(gstInputRow.get("cgst").getAsDouble());
                gstInputDetails.setSgst(gstInputRow.get("sgst").getAsDouble());
                gstInputDetails.setAmount(gstInputRow.get("amount").getAsDouble());
                if (gstInputRow.has("qty") && !gstInputRow.get("qty").getAsString().equalsIgnoreCase(""))
                    gstInputDetails.setQty(gstInputRow.get("qty").getAsDouble());

                gstInputDetails.setFinalAmt(gstInputRow.get("grand_total").getAsDouble());
                gstInputDetails.setBaseAmount(gstInputRow.get("base_amt").getAsDouble());

                gstInputDetails.setStatus(true);
                gstInputDetails.setCreatedBy(users.getId());
                gstInputDetailsRepository.save(gstInputDetails);
            }
            /***** Tax *****/
            List<GstInputDutiesTaxes> gstInputDutiesTaxes = new ArrayList<>();
            String taxStr = request.getParameter("taxCalculation");
            JsonObject duties_taxes = new Gson().fromJson(taxStr, JsonObject.class);
            /*** CGST ****/
            JsonArray cgstList = duties_taxes.getAsJsonArray("cgst");
            if (cgstList != null && cgstList.size() > 0) {
                for (JsonElement taxElement : cgstList) {
                    JsonObject cgstObject = taxElement.getAsJsonObject();
                    LedgerMaster dutiesTaxes = null;
                    String inputGst = cgstObject.get("gst").getAsString();
                    String ledgerName = "INPUT CGST " + inputGst;
                    if (tranxGstInput.getBranch() != null)
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCase(
                                tranxGstInput.getCompany().getId(), tranxGstInput.getBranch().getId(), ledgerName);
                    else
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndBranchIsNull(
                                tranxGstInput.getCompany().getId(), ledgerName);
                    if (dutiesTaxes != null) {
                        GstInputDutiesTaxes inputTax = new GstInputDutiesTaxes();
                        inputTax.setGstInputMaster(tranxGstInput);
                        inputTax.setSupplierLedger(tranxGstInput.getSupplierLedger());
                        inputTax.setPostingLedger(tranxGstInput.getPostingLedger());
                        inputTax.setDutiesTaxes(dutiesTaxes);
                        inputTax.setAmount(Double.parseDouble(cgstObject.get("amt").getAsString()));
                        inputTax.setStatus(true);
                        gstInputDutiesTaxes.add(inputTax);
                    }
                }
            }/*** END CGST ****/

            /**** SGST ****/
            JsonArray sgstList = duties_taxes.getAsJsonArray("sgst");
            if (sgstList != null && sgstList.size() > 0) {
                for (JsonElement taxElement : sgstList) {
                    JsonObject sgstObject = taxElement.getAsJsonObject();
                    LedgerMaster dutiesTaxes = null;
                    String inputGst = sgstObject.get("gst").getAsString();
                    String ledgerName = "INPUT SGST " + inputGst;
                    if (tranxGstInput.getBranch() != null)
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCase(
                                tranxGstInput.getCompany().getId(), tranxGstInput.getBranch().getId(), ledgerName);
                    else
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndBranchIsNull(
                                tranxGstInput.getCompany().getId(), ledgerName);
                    if (dutiesTaxes != null) {
                        GstInputDutiesTaxes inputTax = new GstInputDutiesTaxes();
                        inputTax.setGstInputMaster(tranxGstInput);
                        inputTax.setSupplierLedger(tranxGstInput.getSupplierLedger());
                        inputTax.setPostingLedger(tranxGstInput.getPostingLedger());
                        inputTax.setDutiesTaxes(dutiesTaxes);
                        inputTax.setAmount(Double.parseDouble(sgstObject.get("amt").getAsString()));
                        inputTax.setStatus(true);
                        gstInputDutiesTaxes.add(inputTax);
                    }

                }
            }/*** END SGST ****/


            /**** IGST ****/
            JsonArray igstList = duties_taxes.getAsJsonArray("igst");
            if (igstList != null && igstList.size() > 0) {
                for (JsonElement taxElement : igstList) {
                    JsonObject igstObject = taxElement.getAsJsonObject();
                    LedgerMaster dutiesTaxes = null;
                    String inputGst = igstObject.get("gst").getAsString();
                    String ledgerName = "INPUT IGST " + inputGst;
                    if (tranxGstInput.getBranch() != null)
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCase(
                                tranxGstInput.getCompany().getId(), tranxGstInput.getBranch().getId(), ledgerName);
                    else
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndBranchIsNull(
                                tranxGstInput.getCompany().getId(), ledgerName);
                    if (dutiesTaxes != null) {
                        GstInputDutiesTaxes inputTax = new GstInputDutiesTaxes();
                        inputTax.setGstInputMaster(tranxGstInput);
                        inputTax.setSupplierLedger(tranxGstInput.getSupplierLedger());
                        inputTax.setPostingLedger(tranxGstInput.getPostingLedger());
                        inputTax.setDutiesTaxes(dutiesTaxes);
                        inputTax.setAmount(Double.parseDouble(igstObject.get("amt").getAsString()));
                        inputTax.setStatus(true);
                        gstInputDutiesTaxes.add(inputTax);
                    }
                }
            }/*** END IGST ****/
            gstInputDutiesTaxesRepository.saveAll(gstInputDutiesTaxes);
        } catch (Exception e) {
            e.printStackTrace();
            gstInputLogger.error("Error in create GST Input :->" + e.getMessage());
            response.addProperty("message", "Error in GST Input creation");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        response.addProperty("message", "Gst Input created successfully");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        return response;
    }

    public JsonObject gstInputList(HttpServletRequest request) {
        JsonArray result = new JsonArray();
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        List<GstInputMaster> gstInput = new ArrayList<>();
        if (users.getBranch() != null) {
            gstInput = gstInputMasterRepository.
                    findByCompanyIdAndBranchIdAndStatusOrderByIdDesc(users.getCompany().getId(), users.getBranch().getId(), true);
        } else {
            gstInput = gstInputMasterRepository.
                    findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(users.getCompany().getId(), true);
        }

        for (GstInputMaster vouchers : gstInput) {
            JsonObject response = new JsonObject();
            response.addProperty("id", vouchers.getId());
            response.addProperty("transaction_dt", vouchers.getTranxDate().toString());
            response.addProperty("gst_input_sr_no", vouchers.getVoucherSrNo());
            response.addProperty("narrations", vouchers.getNarrations());
            response.addProperty("gst_input_no", vouchers.getVoucherNo());
            response.addProperty("total_amt", vouchers.getTotalAmount());
            response.addProperty("supplier_ledger_id", vouchers.getSupplierLedger().getId());
            response.addProperty("supplier_ledger_name", vouchers.getSupplierLedger().getLedgerName());
            response.addProperty("posting_ledger_id", vouchers.getPostingLedger().getId());
            response.addProperty("posting_ledger_name", vouchers.getPostingLedger().getLedgerName());
            result.add(response);
        }

        JsonObject output = new JsonObject();
        output.addProperty("message", "success");
        output.addProperty("responseStatus", HttpStatus.OK.value());
        output.add("data", result);
        return output;
    }

    public JsonObject getGstInputById(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(request.getHeader("Authorization").substring(7));
        List<GstInputDetails> list = new ArrayList<>();

        JsonObject finalResult = new JsonObject();
        try {
            Long gstInputId = Long.parseLong(request.getParameter("id"));
            GstInputMaster gstInputMaster = gstInputMasterRepository.findByIdAndStatus(gstInputId, true);
            list = gstInputDetailsRepository.findByGstInputMasterIdAndStatus(gstInputMaster.getId(), true);
            finalResult.addProperty("id", gstInputMaster.getId());
            finalResult.addProperty("voucher_no", gstInputMaster.getVoucherNo());
            finalResult.addProperty("voucher_sr_no", gstInputMaster.getVoucherSrNo());
            finalResult.addProperty("transaction_dt", gstInputMaster.getTranxDate().toString());
            finalResult.addProperty("voucher_dt", gstInputMaster.getVoucherDate().toString());
            finalResult.addProperty("grand_total", gstInputMaster.getTotalAmount());
            finalResult.addProperty("narration", gstInputMaster.getNarrations());
            finalResult.addProperty("totalcgst", gstInputMaster.getTotalCgst());
            finalResult.addProperty("totalsgst", gstInputMaster.getTotalSgst());
            finalResult.addProperty("totaligst", gstInputMaster.getTotalIgst());
            finalResult.addProperty("totaligst", gstInputMaster.getTotalIgst());
            finalResult.addProperty("partyNameId", gstInputMaster.getSupplierLedger().getId());
            finalResult.addProperty("postingAccId", gstInputMaster.getPostingLedger().getId());
            finalResult.addProperty("pay_mode", gstInputMaster.getPaymentModeMaster() != null ?
                    gstInputMaster.getPaymentModeMaster().getId().toString() : "");
            finalResult.addProperty("round_off_amt", gstInputMaster.getRoundOff());
            JsonArray row = new JsonArray();
            if (list.size() > 0) {
                for (GstInputDetails mdetails : list) {
                    JsonObject details = new JsonObject();
                    details.addProperty("details_id", mdetails.getId());
                    details.addProperty("name", mdetails.getParticular());
//                    details.addProperty("hsn_selected", mdetails.getProductHsn().getId());
                    details.addProperty("tax_selected", mdetails.getTaxMaster().getId());
                    details.addProperty("amount", mdetails.getAmount());
                    details.addProperty("gst", mdetails.getGstInputMaster().getId());
                    details.addProperty("igst", mdetails.getIgst());
                    details.addProperty("qty", mdetails.getQty() != null ? mdetails.getQty().toString() : "");
                    details.addProperty("cgst", mdetails.getCgst());
                    details.addProperty("sgst", mdetails.getSgst());

                    row.add(details);
                }
            }

            finalResult.addProperty("message", "success");
            finalResult.addProperty("responseStatus", HttpStatus.OK.value());
            finalResult.add("row", row);

        } catch (DataIntegrityViolationException e) {
            e.printStackTrace();
            gstInputLogger.error("Error in getContraById" + e.getMessage());
            System.out.println(e.getMessage());
            e.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.CONFLICT.value());
        } catch (Exception e1) {
            e1.printStackTrace();
            gstInputLogger.error("Error in getContraById" + e1.getMessage());
            System.out.println(e1.getMessage());
            e1.printStackTrace();
            finalResult.addProperty("message", "error");
            finalResult.addProperty("responseStatus", HttpStatus.FORBIDDEN.value());
        }
        return finalResult;
    }

    public JsonObject updateGstInput(HttpServletRequest request) {
        Users users = jwtRequestFilter.getUserDataFromToken(
                request.getHeader("Authorization").substring(7));
        Map<String, String[]> paramMap = request.getParameterMap();
        JsonObject response = new JsonObject();
        GstInputMaster gstInputMaster = gstInputMasterRepository.findByIdAndStatus(
                Long.parseLong(request.getParameter("id")), true);
        Branch branch = null;
        try {
            if (users.getBranch() != null)
                branch = users.getBranch();
            Company company = users.getCompany();
            gstInputMaster.setBranch(branch);
            gstInputMaster.setCompany(company);
            gstInputMaster.setStatus(true);
            LocalDate tranxDate = LocalDate.parse(request.getParameter("transaction_dt"));
            LocalDate voucherDate = LocalDate.parse(request.getParameter("voucher_dt"));
            /* fiscal year mapping */
            FiscalYear fiscalYear = generateFiscalYear.getFiscalYear(voucherDate);
            if (fiscalYear != null) {
                gstInputMaster.setFiscalYear(fiscalYear);
            }
            gstInputMaster.setTranxDate(tranxDate);
            gstInputMaster.setVoucherDate(voucherDate);
            gstInputMaster.setVoucherNo(request.getParameter("voucher_no"));
            gstInputMaster.setTotalAmount(Double.parseDouble(request.getParameter("grand_total")));
            if (paramMap.containsKey("narration"))
                gstInputMaster.setNarrations(request.getParameter("narration"));
            gstInputMaster.setCreatedBy(users.getId());
            gstInputMaster.setTotalCgst(Double.parseDouble(request.getParameter("totalcgst")));
            gstInputMaster.setTotalSgst(Double.parseDouble(request.getParameter("totalsgst")));
            gstInputMaster.setTotalIgst(Double.parseDouble(request.getParameter("totaligst")));
            LedgerMaster supplier = ledgerMasterRepository.findByIdAndStatus(Long.parseLong(
                    request.getParameter("partyNameId")), true);
            gstInputMaster.setSupplierLedger(supplier);
            LedgerMaster postingAcct = ledgerMasterRepository.findByIdAndStatus(Long.parseLong(
                    request.getParameter("postingAccId")), true);
            gstInputMaster.setPostingLedger(postingAcct);
            PaymentModeMaster paymentModeMaster = paymentModeMasterRepository.findById(Long.parseLong(
                    request.getParameter("pay_mode"))).get();
            gstInputMaster.setPaymentModeMaster(paymentModeMaster);
            LedgerMaster roundoff = null;
            if (users.getBranch() != null)
                roundoff = ledgerMasterRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCase(
                        users.getCompany().getId(), users.getBranch().getId(), "Round off");
            else
                roundoff = ledgerMasterRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndBranchIsNull(
                        users.getCompany().getId(), "Round off");
            gstInputMaster.setRoundOff(Double.parseDouble(request.getParameter("round_off_amt")));
            gstInputMaster.setRoundOffLedger(roundoff);
            GstInputMaster tranxGstInput = gstInputMasterRepository.save(gstInputMaster);

            /**** Details  ****/
            String jsonStr = request.getParameter("rows");
            JsonParser parser = new JsonParser();
            JsonArray row = parser.parse(jsonStr).getAsJsonArray();
            for (int i = 0; i < row.size(); i++) {
                JsonObject gstInputRow = row.get(i).getAsJsonObject();
                Long details_id = gstInputRow.get("details_id").getAsLong();
                GstInputDetails gstInputDetails = new GstInputDetails();
                if (details_id != 0) {
                    gstInputDetails = gstInputDetailsRepository.findByIdAndStatus(details_id, true);
                }
                gstInputDetails.setGstInputMaster(tranxGstInput);
                gstInputDetails.setParticular(gstInputRow.get("name").getAsString());
//                ProductHsn hsn = productHsnRepository.findByIdAndStatus(
//                        gstInputRow.get("hsn_selected").getAsLong(), true);
//                gstInputDetails.setHsnNo(hsn.getHsnNumber());
//                gstInputDetails.setProductHsn(hsn);
                TaxMaster taxMaster = taxMasterRepository.findByIdAndStatus(
                        gstInputRow.get("tax_selected").getAsLong(), true);
                gstInputDetails.setTaxMaster(taxMaster);
                gstInputDetails.setIgst(gstInputRow.get("igst").getAsDouble());
                gstInputDetails.setCgst(gstInputRow.get("cgst").getAsDouble());
                gstInputDetails.setSgst(gstInputRow.get("sgst").getAsDouble());
                gstInputDetails.setAmount(gstInputRow.get("amount").getAsDouble());
                if (gstInputRow.has("qty") && !gstInputRow.get("qty").getAsString().equalsIgnoreCase(""))
                    gstInputDetails.setQty(gstInputRow.get("qty").getAsDouble());

                gstInputDetails.setFinalAmt(gstInputRow.get("grand_total").getAsDouble());
                gstInputDetails.setStatus(true);
                gstInputDetails.setCreatedBy(users.getId());
                gstInputDetailsRepository.save(gstInputDetails);
            }
            /***** Delete Row functionality *****/
            if(paramMap.containsKey("rowDelDetailsIds")){
                String dJsonStr = request.getParameter("rowDelDetailsIds");
                JsonParser dParser = new JsonParser();
                JsonArray dRow = dParser.parse(dJsonStr).getAsJsonArray();
                for (int i = 0; i < dRow.size(); i++) {
                    JsonObject gstInputRow = dRow.get(i).getAsJsonObject();
                    Long del_id = gstInputRow.get("del_id").getAsLong();
                    GstInputDetails gstInputDetails = gstInputDetailsRepository.findByIdAndStatus(del_id, true);
                    if(gstInputDetails != null){
                        gstInputDetails.setStatus(false);
                        gstInputDetailsRepository.save(gstInputDetails);
                    }
                }
            }

            /***** Tax *****/
            List<GstInputDutiesTaxes> gstInputDutiesTaxes = new ArrayList<>();
            String taxStr = request.getParameter("taxCalculation");
            JsonObject duties_taxes = new Gson().fromJson(taxStr, JsonObject.class);
            /*** CGST ****/
            JsonArray cgstList = duties_taxes.getAsJsonArray("cgst");
            if (cgstList != null && cgstList.size() > 0) {
                for (JsonElement taxElement : cgstList) {
                    JsonObject cgstObject = taxElement.getAsJsonObject();
                    LedgerMaster dutiesTaxes = null;
                    String inputGst = cgstObject.get("gst").getAsString();
                    String ledgerName = "INPUT CGST " + inputGst;
                    if (tranxGstInput.getBranch() != null)
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCase(
                                tranxGstInput.getCompany().getId(), tranxGstInput.getBranch().getId(), ledgerName);
                    else
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndBranchIsNull(
                                tranxGstInput.getCompany().getId(), ledgerName);
                    if (dutiesTaxes != null) {
                        GstInputDutiesTaxes inputTax = new GstInputDutiesTaxes();
                        inputTax.setGstInputMaster(tranxGstInput);
                        inputTax.setSupplierLedger(tranxGstInput.getSupplierLedger());
                        inputTax.setPostingLedger(tranxGstInput.getPostingLedger());
                        inputTax.setDutiesTaxes(dutiesTaxes);
                        inputTax.setAmount(Double.parseDouble(cgstObject.get("amt").getAsString()));
                        inputTax.setStatus(true);
                        gstInputDutiesTaxes.add(inputTax);
                    }
                }
            }/*** END CGST ****/

            /**** SGST ****/
            JsonArray sgstList = duties_taxes.getAsJsonArray("sgst");
            if (sgstList != null && sgstList.size() > 0) {
                for (JsonElement taxElement : sgstList) {
                    JsonObject sgstObject = taxElement.getAsJsonObject();
                    LedgerMaster dutiesTaxes = null;
                    String inputGst = sgstObject.get("gst").getAsString();
                    String ledgerName = "INPUT SGST " + inputGst;
                    if (tranxGstInput.getBranch() != null)
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCase(
                                tranxGstInput.getCompany().getId(), tranxGstInput.getBranch().getId(), ledgerName);
                    else
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndBranchIsNull(
                                tranxGstInput.getCompany().getId(), ledgerName);
                    if (dutiesTaxes != null) {
                        GstInputDutiesTaxes inputTax = new GstInputDutiesTaxes();
                        inputTax.setGstInputMaster(tranxGstInput);
                        inputTax.setSupplierLedger(tranxGstInput.getSupplierLedger());
                        inputTax.setPostingLedger(tranxGstInput.getPostingLedger());
                        inputTax.setDutiesTaxes(dutiesTaxes);
                        inputTax.setAmount(Double.parseDouble(sgstObject.get("amt").getAsString()));
                        inputTax.setStatus(true);
                        gstInputDutiesTaxes.add(inputTax);
                    }

                }
            }/*** END SGST ****/


            /**** IGST ****/
            JsonArray igstList = duties_taxes.getAsJsonArray("igst");
            if (igstList != null && igstList.size() > 0) {
                for (JsonElement taxElement : igstList) {
                    JsonObject igstObject = taxElement.getAsJsonObject();
                    LedgerMaster dutiesTaxes = null;
                    String inputGst = igstObject.get("gst").getAsString();
                    String ledgerName = "INPUT IGST " + inputGst;
                    if (tranxGstInput.getBranch() != null)
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndBranchIdAndLedgerNameIgnoreCase(
                                tranxGstInput.getCompany().getId(), tranxGstInput.getBranch().getId(), ledgerName);
                    else
                        dutiesTaxes = ledgerMasterRepository.findByCompanyIdAndLedgerNameIgnoreCaseAndBranchIsNull(
                                tranxGstInput.getCompany().getId(), ledgerName);
                    if (dutiesTaxes != null) {
                        GstInputDutiesTaxes inputTax = new GstInputDutiesTaxes();
                        inputTax.setGstInputMaster(tranxGstInput);
                        inputTax.setSupplierLedger(tranxGstInput.getSupplierLedger());
                        inputTax.setPostingLedger(tranxGstInput.getPostingLedger());
                        inputTax.setDutiesTaxes(dutiesTaxes);
                        inputTax.setAmount(Double.parseDouble(igstObject.get("amt").getAsString()));
                        inputTax.setStatus(true);
                        gstInputDutiesTaxes.add(inputTax);
                    }
                }
            }/*** END IGST ****/
            gstInputDutiesTaxesRepository.saveAll(gstInputDutiesTaxes);
        } catch (Exception e) {
            e.printStackTrace();
            gstInputLogger.error("Error in create GST Input :->" + e.getMessage());
            response.addProperty("message", "Error in GST Input creation");
            response.addProperty("responseStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
        response.addProperty("message", "Gst Input updated   successfully");
        response.addProperty("responseStatus", HttpStatus.OK.value());
        return response;
    }
}
