"use client"

import { useEffect, useRef, useState } from "react"
import { usePathname } from "next/navigation"
import { HubConnectionBuilder } from "@microsoft/signalr"
import { Button } from "@/components/ui/button"
import { LayoutWrapper } from "@/components/layout-wrapper"
import { DashboardStats } from "@/components/dashboard-stats"
import { useAuth } from "@/hooks/use-auth"
import type { Bank, Check, User } from "@/lib/db"
import { API_BASE } from "@/lib/config"

type Region = { id: number; name: string; wilayas: string[] }

const EMPTY_STATS = {
  totalAmount: 0,
  totalChecks: 0,
  checksByBank: {} as Record<string, number>,
  amountByUser: {} as Record<string, number>,
}

interface DashboardData {
  stats: typeof EMPTY_STATS
  checks: Check[]
  users: User[]
  regions: Region[]
  banks: Bank[]
}

const INITIAL_DATA: DashboardData = {
  stats: EMPTY_STATS,
  checks: [],
  users: [],
  regions: [],
  banks: [],
}

const REFRESH_INTERVAL_MS = 30_000

const getStoredToken = () => {
  try {
    return localStorage.getItem("jwt")
  } catch {
    return null
  }
}

const authedFetch = (path: string) => {
  const token = getStoredToken()
  const headers: Record<string, string> = {}
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  
  return fetch(`${API_BASE}${path}`, {
    credentials: "include",
    cache: "no-store",
    headers,
  })
}
export default function DashboardPage() {
  const { user, isLoading: isAuthLoading, status } = useAuth({ requireAuth: true, redirectTo: "/login" })
  const pathname = usePathname()
  const [data, setData] = useState<DashboardData>(INITIAL_DATA)
  const [isFetching, setIsFetching] = useState(false)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const isMountedRef = useRef(true)
  const latestUserRef = useRef<User | null>(null)
  const loadDataTimerRef = useRef<NodeJS.Timeout | null>(null)
  const retryCountRef = useRef(0)
  const pathnameRef = useRef(pathname)
  const hasLoadedRef = useRef(false)

  useEffect(() => {
    return () => {
      isMountedRef.current = false
      if (loadDataTimerRef.current) {
        clearTimeout(loadDataTimerRef.current)
      }
    }
  }, [])

  useEffect(() => {
    latestUserRef.current = user
    retryCountRef.current = 0
  }, [user])
  
  // loadData ne change jamais, utilise latestUserRef
  const loadData = async (options?: { silent?: boolean }) => {
    const currentUser = latestUserRef.current
    if (!currentUser || !isMountedRef.current) {
      return
    }

    // Vérifier que le token est disponible
    const token = getStoredToken()
    if (!token) {
      if (retryCountRef.current < 20) {
        retryCountRef.current++
        console.warn(`Dashboard: No token available, retry ${retryCountRef.current}/20 in 100ms...`)
        if (loadDataTimerRef.current) {
          clearTimeout(loadDataTimerRef.current)
        }
        loadDataTimerRef.current = setTimeout(() => {
          if (isMountedRef.current && latestUserRef.current) {
            loadData(options)
          }
        }, 100)
      } else {
        console.error("Dashboard: Token not available after 20 retries")
      }
      return
    }

    // Reset retry count quand on a un token
    retryCountRef.current = 0

    const showLoader = !options?.silent

    if (showLoader) {
      setIsFetching(true)
      setFetchError(null)
    }

    const parseResponse = async <T,>(response: Response, fallback: T, parser?: (payload: unknown) => T) => {
      if (!response.ok) {
        const details = await response.text().catch(() => "")
        console.error("Dashboard fetch failed:", response.url, response.status, details)
        return fallback
      }

      const payload = await response.json().catch(() => null)
      if (parser) {
        try {
          return parser(payload)
        } catch (error) {
          console.error("Dashboard parser error:", error)
          return fallback
        }
      }
      return (payload as T) ?? fallback
    }

    try {
      const [statsRes, checksRes, usersRes, regionsRes, banksRes] = await Promise.all([
        authedFetch("/api/checks/stats"),
        authedFetch("/api/checks"),
        authedFetch("/api/users"),
        authedFetch("/api/regions"),
        authedFetch("/api/banks"),
      ])

      if (!isMountedRef.current || !latestUserRef.current) {
        return
      }

      const stats = await parseResponse<typeof EMPTY_STATS>(statsRes, EMPTY_STATS)
      const checks = await parseResponse<Check[]>(checksRes, [] as Check[], (payload) =>
        Array.isArray(payload) ? (payload as Check[]) : ([] as Check[]),
      )
      const users = await parseResponse<User[]>(usersRes, [] as User[], (payload) =>
        Array.isArray(payload) ? (payload as User[]) : ([] as User[]),
      )
      const regions = await parseResponse<Region[]>(regionsRes, [] as Region[], (payload) =>
        Array.isArray(payload)
          ? (payload as any[]).map(r => ({ id: r.id, name: r.name, wilayas: r.villes ?? r.wilayas ?? [] }))
          : ([] as Region[]),
      )
      const banks = await parseResponse<Bank[]>(banksRes, [] as Bank[], (payload) => {
        if (payload && typeof payload === "object" && Array.isArray((payload as { banks?: Bank[] }).banks)) {
          return ((payload as { banks?: Bank[] }).banks ?? []) as Bank[]
        }
        return [] as Bank[]
      })

      if (!isMountedRef.current || !latestUserRef.current) {
        return
      }

      setData({ stats, checks, users, regions, banks })
      setFetchError(null)
    } catch (error) {
      console.error("Dashboard data error:", error)
      if (isMountedRef.current) {
        setFetchError("Impossible de charger les données du tableau de bord")
      }
    } finally {
      if (showLoader && isMountedRef.current) {
        setIsFetching(false)
      }
    }
  }
  
  // Chargement des données dès que l'utilisateur est authentifié ET à chaque changement de pathname
  useEffect(() => {
    const wasOnDashboard = pathnameRef.current === "/dashboard"
    const nowOnDashboard = pathname === "/dashboard"
    pathnameRef.current = pathname
    
    if (!user || status !== "authenticated") {
      return
    }
    
    // Si on revient sur le dashboard ou c'est la première fois
    if (nowOnDashboard && (!wasOnDashboard || !hasLoadedRef.current)) {
      console.log("[Dashboard] Loading data", { wasOnDashboard, nowOnDashboard, hasLoaded: hasLoadedRef.current })
      hasLoadedRef.current = true
      loadData()
    }
    
    // Toujours mettre en place l'intervalle quand on est sur le dashboard
    if (nowOnDashboard) {
      const intervalId = setInterval(() => loadData({ silent: true }), REFRESH_INTERVAL_MS)
      return () => {
        clearInterval(intervalId)
      }
    }
  }, [user, status, pathname])

  useEffect(() => {
    if (!user || status !== "authenticated") {
      return
    }

    // Vérifier que le token existe avant de démarrer SignalR
    const token = getStoredToken()
    if (!token) {
      console.warn("SignalR: No token found, skipping connection")
      return
    }

    const connection = new HubConnectionBuilder()
      .withUrl(`${API_BASE}/hubs/check-updates`, { 
        withCredentials: true,
        accessTokenFactory: () => token
      })
      .withAutomaticReconnect([0, 2000, 5000, 10000])
      .build()

    const handleRealtimeUpdate = () => {
      loadData({ silent: true })
    }

    connection.on("checkCreated", handleRealtimeUpdate)
    connection.on("checkStatusUpdated", handleRealtimeUpdate)

    // Démarrer la connexion avec un délai pour s'assurer que l'auth est complète
    const timeoutId = setTimeout(() => {
      connection
        .start()
        .then(() => console.log("SignalR connected"))
        .catch((error) => {
          console.error("SignalR connection error:", error)
          // Ne pas bloquer l'app, juste logger l'erreur
        })
    }, 500)

    return () => {
      clearTimeout(timeoutId)
      connection.off("checkCreated", handleRealtimeUpdate)
      connection.off("checkStatusUpdated", handleRealtimeUpdate)
      connection
        .stop()
        .catch((error) => console.error("SignalR stop error:", error))
    }
  }, [user, status])

  if (isAuthLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-sm text-muted-foreground">Vérification de la session...</p>
      </div>
    )
  }

  if (!user || status !== "authenticated") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-sm text-muted-foreground">Redirection...</p>
      </div>
    )
  }

  return (
    <LayoutWrapper user={user}>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Tableau de Bord</h1>
          </div>
          <Button 
            onClick={() => window.location.reload()} 
            variant="outline"
          >
            Actualiser
          </Button>
        </div>
        {fetchError && <p className="text-sm text-destructive">{fetchError}</p>}
        {isFetching ? (
          <div className="rounded-lg border border-dashed border-gray-200 p-6 text-sm text-muted-foreground">
            Chargement des statistiques...
          </div>
        ) : (
          <DashboardStats
            stats={data.stats}
            checks={data.checks}
            users={data.users}
            currentUser={user}
            regions={data.regions}
            banks={data.banks}
          />
        )}
      </div>
    </LayoutWrapper>
  )
}
