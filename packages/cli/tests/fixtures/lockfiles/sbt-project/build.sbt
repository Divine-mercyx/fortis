ThisBuild / scalaVersion := "2.13.12"
ThisBuild / organization := "com.acme.pay"

val circeVersion = "0.14.6"

lazy val root = (project in file("."))
  .settings(
    name := "ledger",
    libraryDependencies ++= Seq(
      "org.typelevel" %% "cats-core" % "2.10.0",
      "io.circe" %% "circe-core" % circeVersion,
      "io.circe" %% "circe-parser" % circeVersion,
      "org.postgresql" % "postgresql" % "42.5.0",
      "com.typesafe.akka" %% "akka-http" % "10.5.+",
      "org.scala-js" %%% "scalajs-dom" % "2.8.0",
      "org.scalatest" %% "scalatest" % "3.2.17" % Test
    ),
    libraryDependencies += Dependencies.http4sServer
  )
