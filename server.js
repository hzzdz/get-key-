require("dotenv").config();

const express = require("express");

const crypto = require("crypto");

const app = express();

const PORT = Number(process.env.PORT || 8787);

app.use(express.json());

/* =========================

   CORS

========================= */

app.use((req, res, next) => {

  res.setHeader("Access-Control-Allow-Origin", "*");

  res.setHeader(

    "Access-Control-Allow-Methods",

    "GET,POST,OPTIONS"

  );

  res.setHeader(

    "Access-Control-Allow-Headers",

    "content-type"

  );

  if (req.method === "OPTIONS") {

    return res.status(204).end();

  }

  next();

});

/* =========================

   TOKEN

========================= */

function base64(text) {

  return Buffer

    .from(text, "utf8")

    .toString("base64");

}

function makeToken(secret, data) {

  const raw = base64(JSON.stringify(data));

  const sig = crypto

    .createHmac("sha256", secret)

    .update(raw)

    .digest("hex");

  return raw + "." + sig;

}

function verifyToken(secret, token) {

  try {

    const parts = String(token || "").split(".");

    if (parts.length !== 2) {

      return null;

    }

    const [raw, sig] = parts;

    const expected = crypto

      .createHmac("sha256", secret)

      .update(raw)

      .digest("hex");

    if (sig.length !== expected.length) {

      return null;

    }

    if (

      !crypto.timingSafeEqual(

        Buffer.from(sig),

        Buffer.from(expected)

      )

    ) {

      return null;

    }

    return JSON.parse(

      Buffer.from(raw, "base64").toString("utf8")

    );

  } catch {

    return null;

  }

}

/* =========================

   CLIENT ID

========================= */

function getClientId(req) {

  const ip =

    req.headers["cf-connecting-ip"] ||

    (req.headers["x-forwarded-for"] || "")

      .split(",")[0]

      .trim() ||

    req.socket.remoteAddress ||

    "unknown";

  const ua =

    req.headers["user-agent"] || "";

  return crypto

    .createHash("sha256")

    .update(ip + "|" + ua)

    .digest("hex");

}

/* =========================

   SUPABASE

========================= */

async function supabase(path, options = {}) {

  const supabaseUrl =

    process.env.SUPABASE_URL;

  const supabaseKey =

    process.env.SUPABASE_KEY;

  if (!supabaseUrl || !supabaseKey) {

    throw new Error(

      "Thiếu SUPABASE_URL hoặc SUPABASE_KEY."

    );

  }

  const response = await fetch(

    supabaseUrl.replace(/\/$/, "") +

      "/rest/v1/" +

      path,

    {

      ...options,

      headers: {

        apikey: supabaseKey,

        Authorization:

          "Bearer " + supabaseKey,

        "Content-Type":

          "application/json",

        ...(options.headers || {})

      }

    }

  );

  const text = await response.text();

  if (!response.ok) {

    throw new Error(

      "Supabase HTTP " +

        response.status +

        ": " +

        text

    );

  }

  return {

    data: text

      ? JSON.parse(text)

      : null,

    headers: response.headers

  };

}

/* =========================

   COUNT FROM SUPABASE

========================= */

function countFromContentRange(

  headers,

  fallback

) {

  const range =

    headers.get("content-range");

  if (!range) {

    return fallback;

  }

  const total =

    range.split("/")[1];

  const number =

    Number(total);

  return Number.isFinite(number)

    ? number

    : fallback;

}

/* =========================

   CLAIM COUNT

========================= */

async function claimCount(clientId) {

  const result = await supabase(

    "claims?client_hash=eq." +

      encodeURIComponent(clientId) +

      "&select=id",

    {

      headers: {

        Prefer: "count=exact"

      }

    }

  );

  return countFromContentRange(

    result.headers,

    Array.isArray(result.data)

      ? result.data.length

      : 0

  );

}

/* =========================

   SHORTENER

========================= */

async function shorten(

  apiUrl,

  apiKey,

  targetUrl

) {

  const url = apiUrl

    .replace(

      "{API_KEY}",

      encodeURIComponent(apiKey)

    )

    .replace(

      "{URL}",

      encodeURIComponent(targetUrl)

    );

  const response =

    await fetch(url);

  if (!response.ok) {

    throw new Error(

      "Shortener HTTP error"

    );

  }

  const data =

    await response.json();

  if (

    data.status !== "success" ||

    !data.shortenedUrl

  ) {

    throw new Error(

      "Shortener không trả shortenedUrl"

    );

  }

  return data.shortenedUrl;

}

/* =========================

   STATS

========================= */

app.get(

  "/api/stats",

  async (req, res) => {

    try {

      const result =

        await supabase(

          "keys?claimed_by=is.null&select=id",

          {

            headers: {

              Prefer: "count=exact"

            }

          }

        );

      const count =

        countFromContentRange(

          result.headers,

          Array.isArray(result.data)

            ? result.data.length

            : 0

        );

      res.json({

        success: true,

        count

      });

    } catch (error) {

      res.status(500).json({

        error:

          error.message ||

          "Không thể lấy số key."

      });

    }

  }

);

/* =========================

   START GET KEY

========================= */

app.get(

  "/api/start",

  async (req, res) => {

    try {

      if (!process.env.TOKEN_SECRET) {

        return res.status(500).json({

          error:

            "Thiếu TOKEN_SECRET."

        });

      }

      if (!process.env.VUOTNHANH_API_KEY) {

        return res.status(500).json({

          error:

            "Thiếu VUOTNHANH_API_KEY."

        });

      }

      if (!process.env.VUOTLINK_API_KEY) {

        return res.status(500).json({

          error:

            "Thiếu VUOTLINK_API_KEY."

        });

      }

      if (!process.env.FRONTEND_URL) {

        return res.status(500).json({

          error:

            "Thiếu FRONTEND_URL."

        });

      }

      const type =

        req.query.type || "free";

      if (

        type !== "free" &&

        type !== "vip"

      ) {

        return res.status(400).json({

          error:

            "Loại key không hợp lệ."

        });

      }

      const clientId =

        getClientId(req);

      const oldClaim =

        await claimCount(clientId);

      if (oldClaim >= 2) {

        return res.status(409).json({

          error:

            "Thiết bị này đã nhận đủ 2 key."

        });

      }

      const now =

        Math.floor(

          Date.now() / 1000

        );

      const token =

        makeToken(

          process.env.TOKEN_SECRET,

          {

            cid: clientId,

            type: type,

            iat: now,

            exp: now + 900

          }

        );

      const callback =

        process.env.FRONTEND_URL

          .replace(/\/$/, "") +

        "/?token=" +

        encodeURIComponent(token);

      let redirectUrl;

      /* FREE */

      if (type === "free") {

        redirectUrl =

          await shorten(

            "https://vuotlink.xyz/api?api={API_KEY}&url={URL}",

            process.env.VUOTLINK_API_KEY,

            callback

          );

      }

      /* VIP */

      else {

        redirectUrl =

          await shorten(

            "https://vuotnhanh.com/api?api={API_KEY}&url={URL}",

            process.env.VUOTNHANH_API_KEY,

            callback

          );

      }

      res.json({

        success: true,

        type: type,

        redirectUrl:

          redirectUrl

      });

    } catch (error) {

      console.error(

        "START ERROR:",

        error

      );

      res.status(500).json({

        error:

          error.message ||

          "Không thể tạo link."

      });

    }

  }

);

/* =========================

   CLAIM KEY

========================= */

app.get(

  "/api/claim",

  async (req, res) => {

    try {

      if (!process.env.TOKEN_SECRET) {

        return res.status(500).json({

          error:

            "Thiếu TOKEN_SECRET."

        });

      }

      const token =

        req.query.token;

      if (!token) {

        return res.status(400).json({

          error:

            "Thiếu token."

        });

      }

      const payload =

        verifyToken(

          process.env.TOKEN_SECRET,

          token

        );

      if (!payload) {

        return res.status(401).json({

          error:

            "Token không tồn tại."

        });

      }

      if (

        payload.type !== "free" &&

        payload.type !== "vip"

      ) {

        return res.status(400).json({

          error:

            "Loại key không hợp lệ."

        });

      }

      const now =

        Math.floor(

          Date.now() / 1000

        );

      if (

        !payload.exp ||

        payload.exp < now

      ) {

        return res.status(401).json({

          error:

            "Token đã hết hạn."

        });

      }

      const clientId =

        getClientId(req);

      if (

        clientId !== payload.cid

      ) {

        return res.status(403).json({

          error:

            "Thiết bị không khớp."

        });

      }

      const oldClaim =

        await claimCount(

          clientId

        );

      if (oldClaim >= 2) {

        return res.status(409).json({

          error:

            "Thiết bị này đã nhận đủ 2 key."

        });

      }

      /* Tìm key chưa nhận */

      const query =

        "keys?type=eq." +

        encodeURIComponent(

          payload.type

        ) +

        "&claimed_by=is.null" +

        "&select=id,key,type" +

        "&order=id.asc" +

        "&limit=1";

      const selected =

        await supabase(query);

      const availableKey =

        Array.isArray(

          selected.data

        )

          ? selected.data[0]

          : null;

      if (!availableKey) {

        return res.status(404).json({

          error:

            payload.type === "vip"

              ? "Kho KEY VIP đã hết."

              : "Kho KEY FREE đã hết."

        });

      }

      const claimedAt =

        now;

      /* Claim key */

      const updatePath =

        "keys?id=eq." +

        encodeURIComponent(

          availableKey.id

        ) +

        "&claimed_by=is.null";

      const updated =

        await supabase(

          updatePath,

          {

            method: "PATCH",

            headers: {

              Prefer:

                "return=representation"

            },

            body: JSON.stringify({

              claimed_by:

                clientId,

              claimed_at:

                claimedAt

            })

          }

        );

      /*

       * Nếu PATCH không trả

       * về dòng nào thì key

       * đã bị người khác lấy.

       */

      if (

        !Array.isArray(

          updated.data

        ) ||

        updated.data.length === 0

      ) {

        return res.status(409).json({

          error:

            "Key vừa được nhận bởi người khác, hãy thử lại."

        });

      }

      /* Lưu claim */

      await supabase(

        "claims",

        {

          method: "POST",

          headers: {

            Prefer:

              "return=minimal"

          },

          body: JSON.stringify({

            client_hash:

              clientId,

            key_id:

              availableKey.id,

            claimed_at:

              claimedAt

          })

        }

      );

      /* Trả key */

      res.json({

        success: true,

        type:

          availableKey.type,

        key:

          availableKey.key

      });

    } catch (error) {

      console.error(

        "CLAIM ERROR:",

        error

      );

      res.status(500).json({

        error:

          error.message ||

          "Không thể cấp key."

      });

    }

  }

);

/* =========================

   HOME

========================= */

app.get(

  "/",

  (req, res) => {

    res.send(

      "GET KEY API ONLINE"

    );

  }

);

/* =========================

   START SERVER

========================= */

app.listen(

  PORT,

  "0.0.0.0",

  () => {

    console.log(

      "GET KEY API listening on port " +

      PORT

    );

  }

);