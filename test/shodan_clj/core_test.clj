;;; Copyright © 2024 Justin Bishop <mail@dissoc.me>

(ns shodan-clj.core-test
  (:require [clojure.test :refer :all]
            [malli.core :as m]
            [malli.provider :as mp]
            [shodan-clj.core :refer :all]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; NOTE: running tests can use credits! ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; the tests are pretty basic and essentially
;; just test that the endpoint responds with
;; something reasonable for the given request.
;; Some endpoints are not currently tested as
;; access is dependent on account type and I
;; currently do not have access.


;; key is grabbed from env
;; TODO: check resources first and if not
;; found then use env
(def shodan-key (System/getenv "SHODAN_KEY"))

(init-client {:key shodan-key})

;;;;;;;;;;;;;;;;;;;;
;; search methods ;;
;;;;;;;;;;;;;;;;;;;;

(deftest host-info-test
  (is (= "8.8.8.8"
         (-> (host-info {:ip-address "8.8.8.8"})
             :ip-str))))

(deftest host-count-test
  (let [result-schema [:map
                       [:matches [:sequential empty?]]
                       [:facets [:map
                                 [:org [:sequential
                                        [:map
                                         [:count number?]
                                         [:value string?]]]]
                                 [:os [:sequential
                                       [:map
                                        [:count number?]
                                        [:value string?]]]]]]
                       [:total number?]]]
    (is (m/validate result-schema (-> (host-count {:query "port:22"
                                                   :facets "org,os"}))))))

(deftest host-search-test
  (let [result-schema [:map
                       [:matches sequential?]
                       [:facets [:map
                                 [:country [:sequential
                                            [:map
                                             [:count number?]
                                             [:value string?]]]]]]
                       [:total number?]]]
    (is (m/validate result-schema (host-search {:query "product:nginx"
                                                :facets "country"})))))

(deftest list-search-facets-test
  (let [result-schema [:sequential string?]]
    (is (m/validate result-schema
                    (list-search-facets)))))

(deftest list-search-filters-test
  (let [result-schema [:sequential string?]]
    (is (m/validate result-schema
                    (list-search-facets)))))

(deftest search-query-tokens-test
  (let [result-schema [:map
                       [:attributes [:map
                                     [:ports [:sequential int?]]]]
                       [:errors sequential?]
                       [:string string?]
                       [:filters [:sequential string?]]]]
    (is (m/validate result-schema
                    (search-query-tokens {:query "Raspbian port:22"})))))

;;;;;;;;;;;;;;;;;;;;;;;;
;; On-Demand Scanning ;;
;;;;;;;;;;;;;;;;;;;;;;;;

(deftest list-ports-test
  (let [result-schema [:sequential int?]]
    (is (m/validate result-schema (list-ports)))))

(deftest list-protocols-test
  (let [result-schema [map?]]
    (is (m/validate result-schema (list-protocols)))))

(deftest scan-test
  (let [result-schema [:map
                       [:count int?]
                       [:id string?]
                       [:credits-left int?]]]
    (is (m/validate result-schema (scan {:ips "8.8.8.8,1.1.1.1"})))))

;; NOTE:  very few accounts have access to this endpoint
;;        it remains untested
;; (deftest scan-internet-test
;;   (let [result-schema [:map
;;                        [:id string?]]]
;;     (is (m/validate result-schema (scan {:port 80 :protocol "http"})))))

(deftest list-created-scans-test
  (let [result-schema [:map
                       [:matches [:sequential
                                  [:map
                                   [:status string?]
                                   [:created string?]
                                   [:status-check string?]
                                   [:credits-left int?]
                                   [:api-key string?]
                                   [:id string?]
                                   [:size int?]]]]
                       [:total int?]]]
    (is (m/validate result-schema (list-created-scans)))))
