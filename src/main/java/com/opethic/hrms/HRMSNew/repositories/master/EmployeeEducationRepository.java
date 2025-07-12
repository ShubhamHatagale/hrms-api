package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.EmployeeEducation;
import org.hibernate.annotations.Cascade;
import org.hibernate.annotations.CascadeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import javax.transaction.Transactional;

public interface EmployeeEducationRepository extends JpaRepository<EmployeeEducation, Long> {
    EmployeeEducation findByIdAndStatus(long id, boolean b);

    @Modifying
    @Transactional
    @Cascade(CascadeType.DELETE)
    @Query(value = "DELETE FROM employee_education_tbl WHERE id=?1", nativeQuery = true)
    void deleteEducationFromEmployee(long id);
}
