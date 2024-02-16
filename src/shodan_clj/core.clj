(ns shodan-clj.core
  (:require
   [hato.client :as hc]
   [hato.middleware :as hm]
   [malli.core :as m]
   [malli.error :as me]
   [shodan-clj.middleware :refer [json-str->clj]]))

(def api-base-url "https://api.shodan.io")

(defonce client-conf
  (atom {:query-params {:key nil}
         :middleware   (conj hm/default-middleware json-str->clj)}))

(defn init-client [{key :key}]
  (swap! client-conf
         (fn [conf]
           (assoc-in conf [:query-params :key] key))))

(defn s-get
  ([url] (s-get url {}))
  ([url {query-params :query-params
         :as          conf}]
   (let [http-conf (-> conf
                       (merge @client-conf)
                       (update  :query-params #(merge % query-params)))]
     (->> http-conf
          (hc/get (str api-base-url url))
          :body))))

(defn s-post [url conf]
  (->> (assoc @client-conf :form-params conf)
       (hc/post (str api-base-url url))
       :body))

(defn s-delete [url conf]
  (->> @client-conf
       (hc/delete (str api-base-url url))
       :body))

(defn s-put [url conf]
  (->> @client-conf
       (hc/put (str api-base-url url))
       :body))

;;;;;;;;;;;;;;;;;;;;;
;; search methods  ;;
;;;;;;;;;;;;;;;;;;;;;

(defn host-info
  "Host Information
  Returns all services that have been found on the given host IP.

  Parameters
  ip: [String] Host IP address
  history (optional): [Boolean] True if all historical banners should be
  returned (default: False)
  minify (optional): [Boolean] True to only return the list of ports and the
  general host information, no banners. (default: False)"
  [{ip-address :ip-address
    history    :history
    minify     :minify
    :as        params}]
  (let [params-schema [:map
                       [:ip-address string?]
                       [:history {:optional true} boolean?]
                       [:minify {:optional true} boolean?]]]
    (if  (m/validate params-schema params)
      (s-get (str "/shodan/host/" ip-address)
             {:query-params (select-keys params [:history :minify])})
      (throw (ex-info "Invalid input"
                      (me/humanize (m/explain params-schema params)))))))

(defn host-count
  "Search Shodan without Results
  This method behaves identical to \"/shodan/host/search\" with the only
  difference that this method does not return any host results, it only returns
  the total number of results that matched the query and any facet information
  that was requested. As a result this method does not consume query credits.

  Parameters
  query: [String] Shodan search query. The provided string is used to search the
  database of banners in Shodan, with the additional option to provide filters
  inside the search query using a \"filter:value\" format. For example, the
  following search query would find Apache Web servers located in Germany:
  \"apache country:DE\".

  facets (optional): [String] A comma-separated list of properties to get
  summary information on. Property names can also be in the format of
  \"property:count\", where \"count\" is the number of facets that will be
  returned for a property (i.e. \"country:100\" to get the top 100 countries for
  a search query). Visit the Shodan website's Facet Analysis page for an
  up-to-date list of available facets:"
  [{query  :query
    facets :facets
    :as    params}]
  (let [params-schema [:map
                       [:query string?]
                       [:facets {:optional true} string?]]]
    (if (m/validate params-schema params)
      (s-get (str "/shodan/host/count")
             {:query-params (select-keys params [:query :facets])})
      (throw (ex-info "Invalid input"
                      (me/humanize (m/explain params-schema params)))))))

(defn host-search
  "Search Shodan
  Search Shodan using the same query syntax as the website and use facets to get
  summary information for different properties.

  Requirements
  This method may use API query credits depending on usage. If any of the
  following criteria are met, your account will be deducted 1 query credit:

  The search query contains a filter.
  Accessing results past the 1st page using the \"page\". For every 100 results
  past the 1st page 1 query credit is deducted.

  Parameters
  query: [String] Shodan search query. The provided string is used to search the
  database of banners in Shodan, with the additional option to provide filters
  inside the search query using a \"filter:value\" format. For example, the
  following search query would find Apache Web servers located in Germany:
  \"apache country:DE\".
  LIST OF FILTERS
  facets (optional): [String] A comma-separated list of properties to get
  summary information on. Property names can also be in the format of
  \"property:count\", where \"count\" is the number of facets that will be
  returned for a property (i.e. \"country:100\" to get the top 100 countries for
  a search query). Visit the Shodan website's Facet Analysis page for an
  up-to-date list of available facets:
  EXPLORE FACETS
  page (optional): [Integer] The page number to page through results 100 at a
  time (default: 1)
  minify (optional): [Boolean] True or False; whether or not to truncate some of
  the larger fields (default: True)"
  [{query  :query
    facets :facets
    page   :page
    minify :minify
    :as    params}]
  (let [params-schema [:map
                       [:query string?]
                       [:facets {:optional true} string?]
                       [:page {:optional true} int?]
                       [:minify {:optional true} boolean?]]]
    (if (m/validate params-schema params)
      (s-get   "/shodan/host/search"
               {:query-params (select-keys params [:query :facets :page :minify])})
      (throw (ex-info "Invalid input"
                      (me/humanize (m/explain params-schema params)))))))

(defn list-search-facets
  "List all search facets
  This method returns a list of facets that can be used to get a breakdown of
  the top values for a property."
  []
  (s-get "/shodan/host/search/facets"))

(defn list-search-filters
  "List all filters that can be used when searching
  This method returns a list of search filters that can be used in the search
  query."
  []
  (s-get "/shodan/host/search/filters"))

(defn search-query-tokens
  "Break the search query into tokens
  This method lets you determine which filters are being used by the query
  string and what parameters were provided to the filters.

  Parameters
  query: [String] Shodan search query. The provided string is used to search the
  database of banners in Shodan, with the additional option to provide filters
  inside the search query using a \"filter:value\" format. For example, the
  following search query would find Apache Web servers located in Germany:
  \"apache country:DE\"."
  [{query :query
    :as   params}]
  (let [params-schema [:map
                       [:query string?]]]
    (if (m/validate params-schema params)
      (s-get   "/shodan/host/search/tokens"
               {:query-params (select-keys params [:query])})
      (throw (ex-info "Invalid input"
                      (me/humanize (m/explain params-schema params)))))))

;;;;;;;;;;;;;;;;;;;;;;;;
;; On-Demand Scanning ;;
;;;;;;;;;;;;;;;;;;;;;;;;

(defn list-ports
  "List all ports that Shodan is crawling on the Internet.
  This method returns a list of port numbers that the crawlers are looking for."
  []
  (s-get "/shodan/ports"))

(defn list-protocols
  "List all protocols that can be used when performing on-demand Internet scans
  via Shodan.
  This method returns an object containing all the protocols that can be used
  when launching an Internet scan."
  []
  (s-get "/shodan/protocols"))

;; TODO Finish this validation. spec doesnt cover
;; string kw for maps

(defn scan
  "Request Shodan to crawl an IP/ netblock
  Use this method to request Shodan to crawl a network.

  Requirements
  This method uses API scan credits: 1 IP consumes 1 scan credit. You must have
  a paid API plan (either one-time payment or subscription) in order to use this
  method.

  Parameters
  ips: [String] A comma-separated list of IPs or netblocks (in CIDR notation)
  that should get crawled.
  service: [Array] A list of services that should get scanned, where a service
  is defined as a [port, protocol]. "
  ;; [{:ips "8.8.8.8" :services [{:port 80 :protocol "http"}]}]
  [{ips      :ips
    services :services
    :as      params}]
  (let [params-schema
        [:map
         [:ips string?]
         [:services {:optional true} string?]]]
    (if (m/validate params-schema params)
      (s-post   "/shodan/scan"
                {:form-params (select-keys params [:ips :services])})
      (throw (ex-info "Invalid input"
                      (me/humanize (m/explain params-schema params)))))))

(defn scan-internet
  "Crawl the Internet for a specific port and protocol using Shodan
  Use this method to request Shodan to crawl the Internet for a specific port.

  Requirements
  This method is restricted to security researchers and companies with a Shodan
  Enterprise Data license. To apply for access to this method as a researcher,
  please email jmath@shodan.io with information about your project. Access is
  restricted to prevent abuse.

  Parameters
  port: [Integer] The port that Shodan should crawl the Internet for.
  protocol: [String] The name of the protocol that should be used to interrogate
  the port. See /shodan/protocols for a list of supported protocols."
  [{port     :port
    protocol :protocol
    :as      params}]
  (let [params-schema [:map
                       [:port int?]
                       [:protocol string?]]]
    (if (m/validate params-schema params)
      (s-post "/shodan/scan/internet" {:form-params params})
      (throw (ex-info "Invalid input"
                      (me/humanize (m/explain params-schema params)))))))

(defn list-created-scans
  ;; Get list of all the created scans
  ;; Returns a listing of all the on-demand scans that are currently active on
  ;; the account
  []
  (s-get "/shodan/scans"))

(defn scan-status
  "Get the status of a scan request
  Check the progress of a previously submitted scan request. Possible values for
  the status are:
  SUBMITTING
  QUEUE
  PROCESSING
  DONE

  Parameters
  id: [String] The unique scan ID that was returned by /shodan/scan."
  [{id  :id
    :as params}]
  (let [params-schema [:map
                       [:id string?]]]
    (if (m/validate params-schema params)
      (s-get (str "/shodan/scan/" id))
      (throw (ex-info "Invalid input"
                      (me/humanize (m/explain params-schema params)))))))
