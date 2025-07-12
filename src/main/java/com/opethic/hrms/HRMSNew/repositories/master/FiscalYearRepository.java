package com.opethic.hrms.HRMSNew.repositories.master;


import com.opethic.hrms.HRMSNew.models.master.FiscalYear;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDate;
import java.util.List;

public interface FiscalYearRepository extends JpaRepository<FiscalYear, Long> {
    // 0 for default and 1 for User defined financial year and month
    @Query(
            value = " SELECT * FROM fiscal_year_tbl WHERE ?1 BETWEEN date_start AND date_end ", nativeQuery = true
    )
    FiscalYear findFiscalYear(LocalDate curDate);

    @Query(
            value = " SELECT YEAR(date_start) FROM fiscal_year_tbl ", nativeQuery = true
    )
    String getStartYear();

    @Query(
            value = " SELECT YEAR(date_end) FROM fiscal_year_tbl ", nativeQuery = true
    )
    String getLastYear();
    @Query(
            value = " SELECT fiscal_year_tbl.date_start,fiscal_year_tbl.date_end FROM fiscal_year_tbl WHERE YEAR(date_start)=?1", nativeQuery = true
    )
    List<FiscalYear> StartAndEndDateofFiscalYear(String startDate);

    @Query(
            value = " select date_start,date_end from fiscal_year_tbl where YEAR(fiscal_year_tbl.date_start) <= YEAR(CURDATE()) ", nativeQuery = true
    )
    List<Object[]> findByStartDateAndEndDateCompanyIdAndBranchIdAndStatus();

    @Query(
            value = " select date_start,date_end from fiscal_year_tbl where YEAR(fiscal_year_tbl.date_start) <= YEAR(CURDATE()) Order by id desc limit 1", nativeQuery = true
    )
    List<Object[]> findByStartDateAndEndDateCompanyIdAndBranchIdAndStatusLimit();

    FiscalYear findTopByOrderByIdDesc();
}
