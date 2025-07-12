package com.opethic.hrms.HRMSNew.controllers.tranx.journal;

import com.google.gson.JsonObject;
import com.opethic.hrms.HRMSNew.services.tranx_service.journal.TranxJournalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController

public class TranxJournalController {
    @Autowired
    private TranxJournalService service;
    /* get last records of voucher journal   */
    @GetMapping(path = "/get_last_record_journal")
    public Object journalLastRecord(HttpServletRequest request) {
        JsonObject result = service.journalLastRecord(request);
        return result.toString();
    }
    /* Create journal */
  @PostMapping(path = "/create_journal")
    public Object createJournal(HttpServletRequest request) {
        JsonObject array = service.createJournal(request);
        return array.toString();
    }


    /* Get List of journal   */
    @GetMapping(path = "/get_journal_list_by_company")
    public Object journalListbyCompany(HttpServletRequest request) {
        JsonObject object = service.journalListbyCompany(request);
        return object.toString();
    }



    /* Get  ledger details of journal   */
    @GetMapping(path = "/get_ledger_list_by_company")
    public Object getledgerDetails(HttpServletRequest request) {
        JsonObject object = service.getledgerDetails(request);
        return object.toString();
    }

    /*Update journal*/
    @PostMapping(path = "/update_journal")
    public Object updateJournal(HttpServletRequest request) {
        JsonObject array = service.updateJournal(request);
        return array.toString();
    }

    /*get journal by id*/
    @PostMapping(path = "/get_journal_by_id")
    public Object getjournalById(HttpServletRequest request) {
        JsonObject array = service.getjournalById(request);
        return array.toString();
    }
    /***** Delete Journal  ****/
    @PostMapping(path = "/delete_journal")
    public Object deleteJournal(HttpServletRequest request) {
        JsonObject object = service.deleteJournal(request);
        return object.toString();
    }


}
