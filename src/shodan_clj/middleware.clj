;;; Copyright © 2024 Justin Bishop <mail@dissoc.me>

(ns shodan-clj.middleware
  (:require
   [camel-snake-kebab.core :as csk]
   [cheshire.core :refer [parse-string]]
   [clojure.walk :refer [postwalk]]))

(defn clojureize-keys [m]
  (let [f (fn [[k v]]
            (if (or (string? k)
                    (keyword? k))
              [(-> k keyword csk/->kebab-case) v]
              [k v]))]
    ;; only apply to maps
    (postwalk (fn [x]
                (if (map? x)
                  (into {} (map f x))
                  x))
              m)))

(defn json-str->clj
  "takes the body json string and updates it to
  clojure keywordized map"
  [client]
  (fn
    ([req]
     (let [{body :body :as resp} (client req)]
       (if (string? body)
         (update resp :body #(->> %
                                  parse-string
                                  clojureize-keys))
         resp)))))
