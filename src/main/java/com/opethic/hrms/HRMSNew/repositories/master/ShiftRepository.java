package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Shift;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ShiftRepository extends JpaRepository<Shift, Long> {
    List<Shift> findAllByStatus(boolean b);
    Shift findByIdAndStatus(long id, boolean b);

    List<Shift> findByCompanyIdAndStatus(Long id, boolean b);

    List<Shift> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);
}
