package com.opethic.hrms.HRMSNew.common;


import com.opethic.hrms.HRMSNew.models.master.FiscalYear;
import com.opethic.hrms.HRMSNew.repositories.master.FiscalYearRepository;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDate;

@Component
@Data
public class GenerateFiscalYear {
    @Autowired
    private FiscalYearRepository fiscalYearRepository;

    public FiscalYear getFiscalYear(LocalDate curDate) {
        FiscalYear fiscalYear = null;
        fiscalYear = fiscalYearRepository.findFiscalYear(curDate);
        return fiscalYear;
    }

    //generating Start years from Start Date
    public String getStartYear() {
        String startYear = null;
        startYear = fiscalYearRepository.getStartYear();
        return startYear;
    }

    //generating Last years from Start Date
    public String getEndYear() {
        String endYear = null;
        endYear = fiscalYearRepository.getLastYear();
        return endYear;
    }

    public void generateFiscalYear() {

    }
}
