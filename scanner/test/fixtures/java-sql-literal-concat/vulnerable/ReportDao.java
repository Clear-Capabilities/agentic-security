package demo;

import javax.persistence.EntityManager;
import java.util.List;

public class ReportDao {
    private EntityManager em;

    public List<?> byOwner(String owner) {
        return em.createNativeQuery(
            "SELECT id, title " +
            "FROM report " +
            "WHERE owner = '" + owner + "'"
        ).getResultList();
    }
}
