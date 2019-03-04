# WebsiteLogin
用于网站密码的加密（包含注册和登录验证）；用于本科毕设的话可着重讲解这部分，是个很大的加分项

使用说明：文件中只给出了password，未给出与数据库交互部分；
如何调用？
注册：调用PasswordHash.createHash(传入用户输入的密码)，该函数会返回一个String类型的哈希码 A:B:C  直接当做password存入数据库即可，取出的时候本文件会自动分割处理。
登录验证：调用PasswordHash.validatePassword(从数据库取出的password字段，用户在前台输入的密码)，返回类型为boolean；
