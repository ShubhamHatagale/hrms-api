package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UsersRepository extends JpaRepository<Users, Long> {
    Users findByUsername(String username);
    Users findByUsernameAndStatus(String username, boolean b);

    List<Users> findByStatus(boolean b);

    Users findByIdAndStatus(long parseLong, boolean b);

    Users findByCompanyIdAndStatus(Long id, boolean b);
    @Query(value = "SELECT * FROM hrms_new_db.users_tbl where company_id=?1 AND status = 1", nativeQuery = true)
    List<Users> getReportingManagersByCompanyId(Long id);
    Users findByCompanyIdAndUserRoleAndStatus(Long id, String admin, boolean b);
    @Query(value = "SELECT * FROM hrms_new_db.users_tbl WHERE company_id=?1 AND status = 1", nativeQuery = true)
    List<Users> getUsersByCompanyId(Long id);

    List<Users> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);
    Users findByCompanyIdAndBranchIdAndUserRoleAndStatus(Long id, Long id1, String badmin, boolean b);

    Users findByCompanyIdAndBranchIsNullAndStatus(Long id, boolean b);
}
