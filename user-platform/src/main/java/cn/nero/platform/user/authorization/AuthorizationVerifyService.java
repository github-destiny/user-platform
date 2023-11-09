package cn.nero.platform.user.authorization;

import com.beust.jcommander.internal.Maps;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.rmi.ServerError;
import java.util.Map;
import java.util.Scanner;

/**
 * @author Nero Claudius
 * @version 1.0.0
 * @Date 2023/11/9
 */
@Slf4j
@Service
public class AuthorizationVerifyService {

    private Map<String, String> userKeys = Maps.newHashMap();

    public String generateAuthUrl (String userName) {
        String secretKey = GoogleGenerator.generateSecretKey();
        userKeys.put(userName, secretKey);
        return GoogleGenerator.getQRBarcode(userName, secretKey);
    }

    public boolean verifyMFACode (String userName, int code) {
        String secretKey = userKeys.get(userName);

        if (Strings.isBlank(secretKey)) {
            throw new RuntimeException("未使用谷歌身份验证器注册!");
        }

        return GoogleGenerator.checkCode(secretKey, code);

    }

    public static void main(String[] args) {
        AuthorizationVerifyService service = new AuthorizationVerifyService();
        String qrCode = service.generateAuthUrl("nero");
        log.info("{}", qrCode);

        Scanner scanner = new Scanner(System.in);
        if (scanner.hasNext()) {
           Integer lineContent = scanner.nextInt();
            if (service.verifyMFACode("nero", lineContent)) {
                System.out.println("验证通过!");
            }
        }

    }

}
