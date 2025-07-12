package com.opethic.hrms.HRMSNew.util;


import com.opethic.hrms.HRMSNew.common.Enums;
import com.opethic.hrms.HRMSNew.config.SystemConfigParameter;
import com.opethic.hrms.HRMSNew.models.master.Employee;
import com.opethic.hrms.HRMSNew.models.master.EmployeePayhead;
import com.opethic.hrms.HRMSNew.models.master.Payhead;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeePayheadRepository;
import com.opethic.hrms.HRMSNew.repositories.master.EmployeeRepository;
import com.opethic.hrms.HRMSNew.repositories.master.PayheadRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Date;
import java.util.List;

import static java.time.temporal.ChronoUnit.SECONDS;

@Service
public class Utility {

    private final EmployeeRepository employeeRepository;
    private final PayheadRepository payheadRepository;
    private final EmployeePayheadRepository employeePayheadRepository;

    public Utility(EmployeeRepository employeeRepository,
                   PayheadRepository payheadRepository,
                   EmployeePayheadRepository employeePayheadRepository) {
        this.employeeRepository = employeeRepository;
        this.payheadRepository = payheadRepository;
        this.employeePayheadRepository = employeePayheadRepository;
    }

    public Double getTimeInDouble(String time){
        String[] timeParts = time.toString().split(":");
        int hours = Integer.parseInt(timeParts[0]);
        int minutes = Integer.parseInt(timeParts[1]);
        return  Double.parseDouble(hours+"."+minutes);
    }

    public LocalTime getTimeDiffFromTimes(LocalTime l1, LocalTime l2) {
        int s = (int) SECONDS.between(l2, l1);
        System.out.println(" s ------------------->----------------------------------- " + s);
        int sec = Math.abs(s % 60);
        int min = Math.abs((s / 60) % 60);
        int hours = Math.abs((s / 60) / 60);

        String strSec = (sec < 10) ? "0" + sec : Integer.toString(sec);
        String strmin = (min < 10) ? "0" + min : Integer.toString(min);
        String strHours = (hours < 10) ? "0" + hours : Integer.toString(hours);

        System.out.println("------------------->----------------------------------- ");
        System.out.println("HH:MM:SS --->>>> " + strHours + ":" + strmin + ":" + strSec);
        System.out.println("------------------->----------------------------------- ");
        return LocalTime.parse(strHours + ":" + strmin + ":" + strSec);
    }

    public String getEmployeeName(Employee employee) {
        String employeeName = employee.getFirstName();
        if (employee.getMiddleName() != null)
            employeeName = employeeName + " " + employee.getMiddleName();
        if (employee.getLastName() != null)
            employeeName = employeeName + " " + employee.getLastName();
        return employeeName;
    }

    public LocalTime getDateTimeDiffInTime(LocalDateTime fromDate, LocalDateTime toDate) throws ParseException {
        System.out.println("fromDate " + fromDate);
        System.out.println("toDate " + toDate);

        System.out.println("fromDate.getSecond() " + fromDate.getSecond());
        SimpleDateFormat df1 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        SimpleDateFormat df2 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm");

        Date d1 = fromDate.getSecond() > 0 ? df1.parse(fromDate.toString()) : df2.parse(fromDate.toString());
        Date d2 = toDate.getSecond() > 0 ? df1.parse(toDate.toString()) : df2.parse(toDate.toString());

        long d = Math.abs(d2.getTime() - d1.getTime());
        Duration duration = Duration.ofMillis(d);
        long seconds1 = duration.getSeconds();
        long HH = (seconds1 / 3600);
        long MM = ((seconds1 % 3600) / 60);
        long SS = (seconds1 % 60);
        String timeInHHMMSS = String.format("%02d:%02d:%02d", HH, MM, SS);
        System.out.println("String.format(\"%02d:%02d:%02d\", HH, MM, SS) " + String.format("%02d:%02d:%02d", HH, MM, SS));

        String totalTime = null;
        if (HH > 23) {
            totalTime = "16:00:00";
        } else {
            totalTime = timeInHHMMSS;
        }
        return LocalTime.parse(totalTime);
    }

    public String getKeyName(String str, boolean isId) {
        str = str.toLowerCase().replace(" ","_");
        if(isId)
            str = str+"_"+"id";
//        System.out.println(str);
        return str;
    }

    public Double getEmployeeWages(Long employeeId) {
        return employeeRepository.getEmployeeSalary(employeeId, LocalDate.now());
    }

    public Enums.PaymentStatus getPaymentStatusEnum(String identifier){
        for(Enums.PaymentStatus e : Enums.PaymentStatus.values())
            if(e.name().equalsIgnoreCase(identifier))
                return e;
        return null;
    }

    public Enums.InstallmentStatus getInstallmentStatusEnum(String identifier){
        for(Enums.InstallmentStatus e : Enums.InstallmentStatus.values())
            if(e.name().equalsIgnoreCase(identifier))
                return e;
        return null;
    }
    public Payhead getPayheadByKey(String key){
        List<Payhead> payheadList = payheadRepository.getPayheadsList();
        for(Payhead payhead1 : payheadList){
            if(payhead1.getName().toLowerCase().contains(key)){
                return payhead1;
            }
        }
        return  null;
    }
    public EmployeePayhead getEmployeePayheadByKey(List<EmployeePayhead> employeePayheadList, String key){
        for(EmployeePayhead employeePayhead : employeePayheadList){
            if(employeePayhead.getPayhead().getName().toLowerCase().contains(key)){
                return employeePayhead;
            }
        }
        return  null;
    }
}
