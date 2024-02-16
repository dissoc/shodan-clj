(defproject shodan-clj "0.1.0-SNAPSHOT"
  :description "shodan api client for clojure"
  :license {:name "Apache License Version 2.0"
            :url "https://www.apache.org/licenses/LICENSE-2.0.txt"}
  :dependencies [[camel-snake-kebab "0.4.3"]
                 [cheshire "5.11.0"]
                 [hato "0.9.0"]
                 [metosin/malli "0.11.0"]
                 [org.clojure/clojure "1.10.3"]]
  :repl-options {:init-ns shodan-clj.core})
