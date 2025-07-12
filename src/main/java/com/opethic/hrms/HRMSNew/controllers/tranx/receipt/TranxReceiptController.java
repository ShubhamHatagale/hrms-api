package com.opethic.hrms.HRMSNew.controllers.tranx.receipt;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.tranx_service.receipt.TranxReceiptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class TranxReceiptController {

    @Autowired
    private TranxReceiptService service;
    /* Count purchase invoices */
    @GetMapping(path = "/get_receipt_invoice_last_records")
    public Object receiptLastRecord(HttpServletRequest request) {
        JsonObject result = service.receiptLastRecord(request);
        return result.toString();
    }
    /* get sundry debtors list and indirect incomes for receipt */
    @PostMapping(path = "/get_sundry_debtors_indirect_incomes")
    public Object getSundryDebtorsAndIndirectIncomes(HttpServletRequest request) {
        JsonObject result = service.getSundryDebtorsAndIndirectIncomes(request);
        return result.toString();
    }
    /* Sundry debtors pending Bills */
//    @PostMapping(path = "/get_debtors_pending_bills")
//    public Object getDebtorsPendingBills(HttpServletRequest request) {
//        JsonObject array = service.getDebtorsPendingBills(request);
//        return array.toString();
//    }
    /* Create Receipt */
    @PostMapping(path = "/create_receipt")
    public Object createReceipt(HttpServletRequest request) {
        JsonObject array = service.createReceipt(request);
        return array.toString();
    }

    /* Get List of receipts   */
   @GetMapping(path = "/get_receipt_list_by_company")
    public Object receiptListbyCompany(HttpServletRequest request) {
       JsonObject object = service.receiptListbyCompany(request);
        return object.toString();
    }

    @PostMapping(path = "/DTReceiptList")
    public Object DTAllowance(@RequestBody Map<String, String> request, HttpServletRequest httpServletRequest) {
        return service.DTReceiptList(request,httpServletRequest);
    }

    @PostMapping(path = "/update_receipt")
    public Object updateReceipt(HttpServletRequest request) {
        JsonObject array = service.updateReceipt(request);
        return array.toString();
    }

    @PostMapping(path = "/get_receipt_by_id")
    public Object getReceiptById(HttpServletRequest request) {
        JsonObject array = service.getReceiptById(request);
        return array.toString();
    }

    /*Check invoice date is between fiscal years*/
    @PostMapping(path = "/checkInvoiceDateIsBetweenFY")
    public Object checkInvoiceDateIsBetweenFY(HttpServletRequest request) {
        return service.checkInvoiceDateIsBetweenFY(request).toString();
    }


//    @GetMapping(path = "/get_receipt_list_by_outlet")
//    public void get_receipt_list_by_outlet(HttpServletRequest request){
//        System.out.println("called fun get_receipt_list_by_outlet");
//    }
    /***** Delete Receipt  ****/
    @PostMapping(path = "/delete_receipt")
    public Object deleteReceipt(@RequestBody Map<String, String> requestParam,HttpServletRequest request) {
        JsonObject object = service.deleteReceipt(requestParam, request);
        return object.toString();
    }
}
