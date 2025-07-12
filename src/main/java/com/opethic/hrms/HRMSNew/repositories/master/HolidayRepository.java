package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Holiday;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface HolidayRepository extends JpaRepository<Holiday,Long> {

    List<Holiday> findAllByCompanyIdAndBranchIdAndStatus(Long companyId, Long branchId, boolean b);

    Holiday findByIdAndStatus(Long holidayId, boolean b);
}
