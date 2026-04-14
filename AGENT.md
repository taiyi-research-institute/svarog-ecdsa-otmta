所有的 `ch.exchange().await.catch(param1, param2)?;`, 都遵循这个规则:
* `param1` 固定为 `"FailedToExchangeMpcMessages"`
* `param2` 要说明报错位置是什么 MPC 场景, 如 keygen, sign 等; 还要说明在第几轮通信报错.

